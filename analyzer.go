// Package vulns implements the Known Vulnerability Scanner: dependencies
// with exact versions are matched against the OSV.dev database.
package vulns

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

const (
	defaultBaseURL = "https://api.osv.dev"
	batchSize      = 1000
	maxDetails     = 400
	detailWorkers  = 8
)

// Analyzer implements the capability.
type Analyzer struct {
	// BaseURL overrides the OSV API endpoint (tests, mirrors).
	BaseURL string
}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Applies declines when no dependency has an exact version.
func (*Analyzer) Applies(in *analyzer.Input) (bool, string) {
	var deps facts.Dependencies
	if ok, _ := in.Evidence.Get(facts.KeyDependencies, &deps); !ok {
		return false, "no dependency inventory"
	}
	for _, p := range deps.Packages {
		if p.Version != "" {
			return true, ""
		}
	}
	return false, "no dependencies with exact versions (add a lockfile to enable vulnerability matching)"
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Vuln is the subset of the OSV schema used here.
type Vuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// Analyze implements analyzer.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	if in.HTTP == nil {
		return nil, errors.New("network access is required")
	}
	base := a.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	var deps facts.Dependencies
	if _, err := in.Evidence.Get(facts.KeyDependencies, &deps); err != nil {
		return nil, err
	}
	var pkgs []facts.Package
	skippedStdlib := false
	for _, p := range deps.Packages {
		if p.Version == "" || p.Ecosystem == "" {
			continue
		}
		// go.mod's "go 1.x" directive is a minimum language version, not
		// the toolchain in use; only a pinned patch version is matchable.
		if p.Ecosystem == "Go" && p.Name == "stdlib" && strings.Count(strings.TrimPrefix(p.Version, "go"), ".") < 2 {
			skippedStdlib = true
			continue
		}
		pkgs = append(pkgs, p)
	}

	hits := make([][]string, len(pkgs)) // vuln IDs per package
	for start := 0; start < len(pkgs); start += batchSize {
		end := min(start+batchSize, len(pkgs))
		if err := a.queryBatch(ctx, in.HTTP, base, pkgs[start:end], hits[start:end]); err != nil {
			return nil, err
		}
	}

	var ids []string
	seen := map[string]bool{}
	for _, hs := range hits {
		for _, id := range hs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	var limits []string
	if len(ids) > maxDetails {
		limits = append(limits, fmt.Sprintf("%d advisories matched; details were fetched for the first %d only.", len(ids), maxDetails))
	}
	details := a.fetchDetails(ctx, in.HTTP, base, ids[:min(len(ids), maxDetails)])

	var findings []finding.Finding
	vulnerable := 0
	for i, p := range pkgs {
		if len(hits[i]) == 0 {
			continue
		}
		if f, ok := packageFinding(p, hits[i], details); ok {
			findings = append(findings, f)
			vulnerable++
		}
	}
	limits = append(limits, "Only dependencies with exact versions (from lockfiles) can be matched. Declared ranges without a lockfile are not checked.")
	if skippedStdlib {
		limits = append(limits, "The Go standard library was not checked: go.mod declares only a minimum language version. Add a toolchain directive (e.g. toolchain go1.25.3) to pin it.")
	}
	return &analyzer.Result{
		Findings:    findings,
		Summary:     fmt.Sprintf("%d of %d versioned packages have known vulnerabilities (%d advisories)", vulnerable, len(pkgs), len(ids)),
		Limitations: limits,
	}, nil
}

func osvName(p facts.Package) (name, version string) {
	name, version = p.Name, p.Version
	if p.Ecosystem == "Go" {
		version = strings.TrimPrefix(version, "v")
		if name == "stdlib" && strings.Count(version, ".") == 1 {
			version += ".0"
		}
	}
	return
}

func (a *Analyzer) queryBatch(ctx context.Context, c *http.Client, base string, pkgs []facts.Package, out [][]string) error {
	queries := make([]osvQuery, len(pkgs))
	for i, p := range pkgs {
		queries[i].Package.Name, queries[i].Version = osvName(p)
		queries[i].Package.Ecosystem = p.Ecosystem
	}
	pending := make([]int, len(pkgs))
	for i := range pending {
		pending[i] = i
	}
	for round := 0; len(pending) > 0 && round < 10; round++ {
		qs := make([]osvQuery, len(pending))
		for j, idx := range pending {
			qs[j] = queries[idx]
		}
		var resp batchResponse
		if err := postJSON(ctx, c, base+"/v1/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
			return fmt.Errorf("OSV query: %w", err)
		}
		if len(resp.Results) != len(qs) {
			return fmt.Errorf("OSV query: got %d results for %d queries", len(resp.Results), len(qs))
		}
		var next []int
		for j, r := range resp.Results {
			idx := pending[j]
			for _, v := range r.Vulns {
				out[idx] = append(out[idx], v.ID)
			}
			if r.NextPageToken != "" {
				queries[idx].PageToken = r.NextPageToken
				next = append(next, idx)
			}
		}
		pending = next
	}
	return nil
}

func (a *Analyzer) fetchDetails(ctx context.Context, c *http.Client, base string, ids []string) map[string]*Vuln {
	out := map[string]*Vuln{}
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range detailWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				var v Vuln
				if err := getJSON(ctx, c, base+"/v1/vulns/"+url.PathEscape(id), &v); err != nil {
					continue
				}
				mu.Lock()
				out[id] = &v
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	return out
}

func postJSON(ctx context.Context, c *http.Client, u string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(c, req, out)
}

func getJSON(ctx context.Context, c *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return do(c, req, out)
}

func do(c *http.Client, req *http.Request, out any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// severityOf returns the severity and the CVSS score (0 when unknown).
func severityOf(v *Vuln) (finding.Severity, float64, bool) {
	if strings.HasPrefix(v.ID, "MAL-") {
		return finding.Critical, 10, true
	}
	best := -1.0
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if sc, ok := CVSS3Score(s.Score); ok && sc > best {
				best = sc
			}
		}
	}
	if best >= 0 {
		return fromScore(best), best, true
	}
	label := ""
	if s, ok := v.DatabaseSpecific["severity"].(string); ok {
		label = s
	}
	for _, af := range v.Affected {
		if s, ok := af.DatabaseSpecific["severity"].(string); ok && label == "" {
			label = s
		}
	}
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return finding.Critical, 0, true
	case "HIGH":
		return finding.High, 0, true
	case "MODERATE", "MEDIUM":
		return finding.Medium, 0, true
	case "LOW":
		return finding.Low, 0, true
	}
	return finding.Medium, 0, false
}

func fromScore(s float64) finding.Severity {
	switch {
	case s >= 9:
		return finding.Critical
	case s >= 7:
		return finding.High
	case s >= 4:
		return finding.Medium
	case s > 0:
		return finding.Low
	}
	return finding.Info
}

// fixedVersion returns the lowest fixed version above current for the package.
func fixedVersion(v *Vuln, p facts.Package, current string) string {
	var fixes []string
	for _, af := range v.Affected {
		if !strings.EqualFold(af.Package.Name, p.Name) {
			continue
		}
		for _, r := range af.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" && compareVersions(f, current) > 0 {
					fixes = append(fixes, f)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}
	sort.Slice(fixes, func(i, j int) bool { return compareVersions(fixes[i], fixes[j]) < 0 })
	return fixes[0]
}

// compareVersions compares dotted numeric versions, ignoring a leading "v"
// and pre-release suffixes. Good enough to order fixed versions.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, s := range strings.Split(v, ".") {
		n, err := strconv.Atoi(strings.TrimLeft(s, "abcdefghijklmnopqrstuvwxyz"))
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func lower(s finding.Severity) finding.Severity {
	switch s {
	case finding.Critical:
		return finding.High
	case finding.High:
		return finding.Medium
	case finding.Medium:
		return finding.Low
	}
	return s
}

// packageFinding groups every advisory affecting one package version into
// a single, actionable finding: "upgrade X to Y".
func packageFinding(p facts.Package, ids []string, details map[string]*Vuln) (finding.Finding, bool) {
	type adv struct {
		id, summary string
		sev         finding.Severity
		score       float64
		known       bool
		fixed       string
		aliases     []string
		refs        []string
	}
	var advs []adv
	_, current := osvName(p)
	for _, id := range ids {
		v := details[id]
		if v == nil {
			advs = append(advs, adv{id: id, sev: finding.Medium, summary: "details unavailable"})
			continue
		}
		if v.Withdrawn != "" {
			continue
		}
		sev, score, known := severityOf(v)
		a := adv{id: id, summary: v.Summary, sev: sev, score: score, known: known, fixed: fixedVersion(v, p, current), aliases: v.Aliases}
		if a.summary == "" {
			a.summary = firstLine(v.Details)
		}
		for _, r := range v.References {
			if r.Type == "ADVISORY" || r.Type == "WEB" {
				a.refs = append(a.refs, r.URL)
				break
			}
		}
		advs = append(advs, a)
	}
	if len(advs) == 0 {
		return finding.Finding{}, false
	}
	sort.Slice(advs, func(i, j int) bool {
		if advs[i].sev.Rank() != advs[j].sev.Rank() {
			return advs[i].sev.Rank() > advs[j].sev.Rank()
		}
		if advs[i].score != advs[j].score {
			return advs[i].score > advs[j].score
		}
		return advs[i].id < advs[j].id
	})
	top := advs[0]
	sev := top.sev
	conf := finding.ConfidenceHigh
	if !top.known {
		conf = finding.ConfidenceMedium
	}
	var tags []string
	if p.Dev {
		sev = lower(sev)
		tags = append(tags, "dev-dependency")
	}
	// Packages declared only in example, docs or test code do not ship.
	if ctx := nonShippingContext(p.Locations); ctx != "" {
		sev = lower(lower(sev))
		tags = append(tags, string(ctx)+"-only")
	}
	fix := ""
	for _, a := range advs {
		if a.fixed != "" && compareVersions(a.fixed, fix) > 0 {
			fix = a.fixed
		}
	}
	malicious := strings.HasPrefix(top.id, "MAL-")
	category := "vulnerability"
	if malicious {
		category = "malicious-package"
	}
	var ev []finding.Evidence
	for _, loc := range p.Locations {
		ev = append(ev, finding.Evidence{Location: finding.Location{Path: loc}, Detail: fmt.Sprintf("resolves %s %s", p.Name, p.Version)})
	}
	var related, refs []string
	var lines []string
	for _, a := range advs {
		related = append(related, a.id)
		refs = append(refs, "https://osv.dev/vulnerability/"+a.id)
		line := fmt.Sprintf("- %s (%s", a.id, a.sev)
		if a.score > 0 {
			line += fmt.Sprintf(", CVSS %.1f", a.score)
		}
		line += ")"
		if len(a.aliases) > 0 {
			line += " " + strings.Join(a.aliases[:min(len(a.aliases), 2)], ", ")
		}
		if a.summary != "" {
			line += ": " + a.summary
		}
		lines = append(lines, line)
	}
	title := fmt.Sprintf("%s %s has %d known vulnerabilit%s", p.Name, p.Version, len(advs), plural(len(advs), "y", "ies"))
	remediation := fmt.Sprintf("Upgrade %s to %s or later and re-run the tests.", p.Name, fix)
	automatable := true
	if fix == "" {
		remediation = fmt.Sprintf("No fixed release of %s is recorded for these advisories. Assess exposure, apply vendor mitigations, or replace the package.", p.Name)
		automatable = false
	}
	if malicious {
		title = fmt.Sprintf("%s %s is a known malicious package", p.Name, p.Version)
		remediation = "Remove the package immediately, rotate every credential available to the build and runtime environments, and investigate for compromise."
		automatable = false
	}
	desc := strings.Join(lines, "\n")
	if direct := p.Direct; direct != nil && !*direct {
		desc = "Transitive dependency. " + desc
	}
	return finding.Finding{
		Dimension: finding.DimSecurity, Category: category, Severity: sev, Confidence: conf,
		Title:                 title,
		Description:           desc,
		Evidence:              ev,
		Component:             p.Name + "@" + p.Version,
		Related:               related,
		Rule:                  &finding.Rule{ID: top.id, Name: top.summary, References: append(refs[:min(len(refs), 5)], top.refs...)},
		Remediation:           &finding.Remediation{Summary: remediation, Automatable: automatable},
		Tags:                  tags,
		FalsePositiveGuidance: "Advisories match on version only. Check whether the vulnerable function is reachable in this application before deprioritising.",
	}, true
}

// nonShippingContext returns the shared context when every location is in
// example, docs or test code, or "" when any location ships.
func nonShippingContext(locs []string) facts.Context {
	var ctx facts.Context
	for _, l := range locs {
		c := facts.PathContext(l)
		if c == facts.ContextProduction {
			return ""
		}
		ctx = c
	}
	return ctx
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\n."); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

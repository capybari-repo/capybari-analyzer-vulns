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
	"time"

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
	// DepsDevURL overrides the deps.dev API endpoint (tests).
	DepsDevURL string
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
		// Declared-only direct dependencies can still be checked for existence.
		if _, ok := depsDevSystem[p.Ecosystem]; ok && p.Direct != nil && *p.Direct {
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
	unknown, registry, checked, err := a.unknownPackages(ctx, in.HTTP, deps.Packages)
	if err != nil {
		limits = append(limits, "Registry existence check incomplete: "+err.Error())
	}
	findings = append(findings, unknown...)
	now := time.Now()
	if in.Now != nil {
		now = in.Now()
	}
	upkeep := maintenanceFindings(registry, checked, now)
	findings = append(findings, upkeep...)
	limits = append(limits, "Only dependencies with exact versions (from lockfiles) can be matched. Declared ranges without a lockfile are not checked.")
	if skippedStdlib {
		limits = append(limits, "The Go standard library was not checked: go.mod declares only a minimum language version. Add a toolchain directive (e.g. toolchain go1.25.3) to pin it.")
	}
	return &analyzer.Result{
		Findings:    findings,
		Summary:     fmt.Sprintf("%d of %d versioned packages have known vulnerabilities (%d advisories); %d of %d direct dependencies not found in their public registry; %d deprecated or without a release in 2+ years", vulnerable, len(pkgs), len(ids), len(unknown), checked, len(upkeep)),
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

// depsDevSystem maps OSV ecosystem names to deps.dev systems.
var depsDevSystem = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "go", "Maven": "maven", "crates.io": "cargo", "NuGet": "nuget", "RubyGems": "rubygems",
}

// unknownPackages asks deps.dev whether each direct dependency exists in its
// public registry. Only a definite 404 counts: names an assistant invented
// ("hallucinated") are exactly the slots attackers register (slopsquatting).
// registryInfo is what deps.dev says about an existing direct dependency.
type registryInfo struct {
	pkg          facts.Package
	lastRelease  time.Time
	deprecated   bool
	deprecReason string
}

// depsDevPackage is the part of the deps.dev GetPackage response we read.
type depsDevPackage struct {
	Versions []struct {
		PublishedAt      time.Time `json:"publishedAt"`
		IsDefault        bool      `json:"isDefault"`
		IsDeprecated     bool      `json:"isDeprecated"`
		DeprecatedReason string    `json:"deprecatedReason"`
	} `json:"versions"`
}

func (a *Analyzer) unknownPackages(ctx context.Context, c *http.Client, pkgs []facts.Package) ([]finding.Finding, []registryInfo, int, error) {
	base := a.DepsDevURL
	if base == "" {
		base = "https://api.deps.dev"
	}
	var todo []facts.Package
	seen := map[string]bool{}
	for _, p := range pkgs {
		sys, ok := depsDevSystem[p.Ecosystem]
		if !ok || p.Direct == nil || !*p.Direct || (p.Ecosystem == "Go" && p.Name == "stdlib") || seen[sys+p.Name] {
			continue
		}
		seen[sys+p.Name] = true
		todo = append(todo, p)
		if len(todo) == 300 {
			break
		}
	}
	var mu sync.Mutex
	var out []finding.Finding
	var infos []registryInfo
	var firstErr error
	jobs := make(chan facts.Package)
	var wg sync.WaitGroup
	for range detailWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				u := fmt.Sprintf("%s/v3/systems/%s/packages/%s", base, depsDevSystem[p.Ecosystem], url.PathEscape(p.Name))
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					continue
				}
				resp, err := c.Do(req)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					// The same response says when the package last released
					// and whether its maintainers deprecated it.
					var dp depsDevPackage
					if json.Unmarshal(body, &dp) == nil && len(dp.Versions) > 0 {
						info := registryInfo{pkg: p}
						for _, v := range dp.Versions {
							if v.PublishedAt.After(info.lastRelease) {
								info.lastRelease = v.PublishedAt
							}
							if v.IsDefault && v.IsDeprecated {
								info.deprecated, info.deprecReason = true, v.DeprecatedReason
							}
						}
						mu.Lock()
						infos = append(infos, info)
						mu.Unlock()
					}
					continue
				}
				if resp.StatusCode != http.StatusNotFound {
					continue
				}
				// An unscoped public name can be registered by anyone, so an
				// invented one is directly exploitable. Scoped npm packages,
				// Maven groups and Go modules are namespaced and often private.
				sev, conf := finding.High, finding.ConfidenceMedium
				if strings.HasPrefix(p.Name, "@") || p.Ecosystem == "Maven" || p.Ecosystem == "Go" {
					sev, conf = finding.Medium, finding.ConfidenceLow
				}
				var ev []finding.Evidence
				for _, l := range p.Locations {
					ev = append(ev, finding.Evidence{Location: finding.Location{Path: l}, Detail: "declares " + p.Name})
				}
				f := finding.Finding{
					Dimension: finding.DimDependencies, Category: "unknown-package", Severity: sev, Confidence: conf,
					Title:                 fmt.Sprintf("%s is not in the public %s registry", p.Name, p.Ecosystem),
					Description:           fmt.Sprintf("The direct dependency %q could not be found in the public %s registry. AI coding assistants sometimes invent plausible package names; if the name is ever registered by someone else, installs pull in their code (\"slopsquatting\").", p.Name, p.Ecosystem),
					Evidence:              ev,
					Component:             p.Name,
					Rule:                  &finding.Rule{ID: "unknown-package", References: []string{"https://deps.dev"}},
					Remediation:           &finding.Remediation{Summary: "Confirm where this package comes from. Remove it if it was invented, or pin it to your private registry (scoped name, .npmrc / pip index URL) so a public package with the same name can never be installed.", Automatable: false},
					FalsePositiveGuidance: "Packages from a private registry or monorepo workspace are legitimately absent from the public registry.",
				}
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}
		}()
	}
	for _, p := range todo {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	sort.Slice(infos, func(i, j int) bool { return infos[i].pkg.Name < infos[j].pkg.Name })
	return out, infos, len(todo), firstErr
}

// staleAfter is how long without any release makes a dependency look
// unmaintained. Finished, stable libraries exist, so confidence is low.
const staleAfter = 2 * 365 * 24 * time.Hour

// maintenanceFindings reports deprecated direct dependencies (one finding
// each) and those with no release in two years (one grouped finding).
func maintenanceFindings(infos []registryInfo, checked int, now time.Time) []finding.Finding {
	var out []finding.Finding
	var stale []registryInfo
	for _, in := range infos {
		p := in.pkg
		loc := finding.Location{}
		if len(p.Locations) > 0 {
			loc.Path = p.Locations[0]
		}
		if in.deprecated {
			reason := in.deprecReason
			if reason == "" {
				reason = "no reason given"
			}
			out = append(out, finding.Finding{
				Dimension: finding.DimDependencies, Category: "deprecated-package", Severity: finding.Medium, Confidence: finding.ConfidenceHigh,
				Title:       fmt.Sprintf("%s is deprecated by its maintainers", p.Name),
				Description: fmt.Sprintf("The latest %s release of %s is marked deprecated (%s). It will not receive fixes.", p.Ecosystem, p.Name, reason),
				Evidence:    []finding.Evidence{{Location: loc, Detail: "deprecated: " + reason}},
				Component:   p.Name,
				Rule:        &finding.Rule{ID: "deprecated-package", References: []string{"https://deps.dev"}},
				Impact:      &finding.Impact{Business: "Bugs and vulnerabilities in it will stay unfixed.", Buyer: finding.BuyerSupportCost},
				Remediation: &finding.Remediation{Summary: "Replace it with the maintained alternative its maintainers recommend."},
			})
			continue
		}
		if !in.lastRelease.IsZero() && now.Sub(in.lastRelease) > staleAfter {
			stale = append(stale, in)
		}
	}
	if len(stale) == 0 {
		return out
	}
	sev := finding.Low
	if len(stale) >= 5 || checked > 0 && len(stale)*4 >= checked {
		sev = finding.Medium
	}
	var ev []finding.Evidence
	for i, in := range stale {
		if i == 20 {
			break
		}
		loc := finding.Location{}
		if len(in.pkg.Locations) > 0 {
			loc.Path = in.pkg.Locations[0]
		}
		ev = append(ev, finding.Evidence{Location: loc, Detail: fmt.Sprintf("%s: last release %s", in.pkg.Name, in.lastRelease.Format("2006-01-02"))})
	}
	out = append(out, finding.Finding{
		Dimension: finding.DimDependencies, Category: "unmaintained-dependency", Severity: sev, Confidence: finding.ConfidenceLow,
		Title:                 fmt.Sprintf("%d of %d direct dependencies have had no release in over 2 years", len(stale), checked),
		Description:           "No new version of these packages has been published for more than two years. Some are simply finished; others are abandoned and will not get fixes.",
		Evidence:              ev,
		Rule:                  &finding.Rule{ID: "unmaintained-dependency", References: []string{"https://deps.dev"}},
		Impact:                &finding.Impact{Buyer: finding.BuyerSupportCost},
		Remediation:           &finding.Remediation{Summary: "Check each package's repository for activity; plan replacements for the abandoned ones."},
		FalsePositiveGuidance: "Small, stable libraries (a single function, a finished spec) may legitimately not need releases.",
	})
	return out
}

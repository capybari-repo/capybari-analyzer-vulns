package vulns_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	vulns "github.com/capybari-repo/capybari-analyzer-vulns"
	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-schemas"
	"gopkg.in/yaml.v3"
)

func TestCapabilityMetadata(t *testing.T) {
	b, err := os.ReadFile("capability.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyzer.ParseCapability(b); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateValue("capability.schema.json", doc); err != nil {
		t.Fatal(err)
	}
}

func TestCVSS3(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, ok := vulns.CVSS3Score(vec)
		if !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", vec, got, ok, want)
		}
	}
	if _, ok := vulns.CVSS3Score("CVSS:4.0/AV:N"); ok {
		t.Error("v4 vectors must not parse as v3")
	}
}

type evidence map[string]any

func (e evidence) Get(k string, out any) (bool, error) {
	v, ok := e[k]
	if !ok {
		return false, nil
	}
	b, _ := json.Marshal(v)
	return true, json.Unmarshal(b, out)
}
func (e evidence) Has(k string) bool { _, ok := e[k]; return ok }

func TestGroupsAdvisoriesPerPackage(t *testing.T) {
	var queries int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			queries++
			var body struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
					Version string                           `json:"version"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			var results []map[string]any
			for _, q := range body.Queries {
				switch q.Package.Name {
				case "lodash":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-aaaa"}, {"id": "GHSA-bbbb"}}})
				case "stdlib":
					if q.Version != "1.22.3" {
						t.Errorf("unexpected Go stdlib version queried: %q", q.Version)
					}
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GO-2023-0001"}}})
				case "demo-only":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-aaaa"}}})
				case "evil-pkg":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "MAL-2024-1"}}})
				default:
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v3/systems/"):
			if strings.Contains(r.URL.Path, "invented-helper") {
				http.NotFound(w, r)
				return
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/lodash"):
				w.Write([]byte(`{"versions":[{"publishedAt":"2021-02-20T15:42:16Z","isDefault":true}]}`))
			case strings.HasSuffix(r.URL.Path, "/request"):
				w.Write([]byte(`{"versions":[{"publishedAt":"2020-02-11T16:35:28Z","isDefault":true,"isDeprecated":true,"deprecatedReason":"request has been deprecated"}]}`))
			default:
				w.Write([]byte(`{"packageKey":{}}`))
			}
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			v := map[string]any{"id": id, "summary": "Issue " + id, "aliases": []string{"CVE-2021-" + id[len(id)-4:]}}
			switch id {
			case "GHSA-aaaa":
				v["severity"] = []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
				v["affected"] = []map[string]any{{"package": map[string]string{"name": "lodash", "ecosystem": "npm"}, "ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}}}}
			case "GHSA-bbbb":
				v["database_specific"] = map[string]string{"severity": "MODERATE"}
				v["affected"] = []map[string]any{{"package": map[string]string{"name": "lodash", "ecosystem": "npm"}, "ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.19"}}}}}}
			}
			json.NewEncoder(w).Encode(v)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	yes, no := true, false
	in := &analyzer.Input{
		Target: analyzer.Target{Kind: analyzer.TargetRepository, Display: "x"},
		Evidence: evidence{facts.KeyDependencies: facts.Dependencies{Packages: []facts.Package{
			{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", Locations: []string{"package-lock.json"}, Direct: &yes},
			{Name: "stdlib", Version: "1.22.3", Ecosystem: "Go", Locations: []string{"go.mod"}},
			{Name: "stdlib", Version: "1.19", Ecosystem: "Go", Locations: []string{"sub/go.mod"}},
			{Name: "demo-only", Version: "1.0.0", Ecosystem: "npm", Locations: []string{"examples/demo/package-lock.json"}},
			{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm", Locations: []string{"package-lock.json"}, Direct: &no, Dev: true},
			{Name: "safe", Version: "1.0.0", Ecosystem: "npm"},
			{Name: "declared-only", Ecosystem: "npm"},
			{Name: "invented-helper", Ecosystem: "npm", Direct: &yes, Locations: []string{"package.json"}},
			{Name: "request", Ecosystem: "npm", Direct: &yes, Locations: []string{"package.json"}},
		}}},
		HTTP: srv.Client(),
		Now:  func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	a := &vulns.Analyzer{BaseURL: srv.URL, DepsDevURL: srv.URL}
	if ok, why := a.Applies(in); !ok {
		t.Fatal(why)
	}
	res, err := a.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if queries != 1 {
		t.Fatalf("expected one batch query, got %d", queries)
	}
	byComp := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byComp[f.Component] = f
	}
	l := byComp["lodash@4.17.15"]
	if l.Severity != finding.Critical || l.Rule.ID != "GHSA-aaaa" || len(l.Related) != 2 || !strings.Contains(l.Remediation.Summary, "4.17.21") {
		t.Fatalf("lodash finding: %+v / %+v", l, l.Remediation)
	}
	if g := byComp["stdlib@1.22.3"]; g.Severity != finding.Medium || g.Confidence != finding.ConfidenceMedium {
		t.Fatalf("unknown-severity advisory should be medium/medium: %+v", g)
	}
	m := byComp["evil-pkg@1.0.0"]
	if m.Category != "malicious-package" || m.Severity != finding.High || !strings.Contains(m.Remediation.Summary, "rotate") {
		t.Fatalf("malicious dev package: %+v", m)
	}
	if d := byComp["demo-only@1.0.0"]; d.Severity != "medium" || d.Tags[0] != "example-only" {
		t.Fatalf("example-only package should drop two levels (critical -> medium): %+v", d)
	}
	u := byComp["invented-helper"]
	if u.Category != "unknown-package" || u.Confidence != finding.ConfidenceMedium || !strings.Contains(u.Description, "slopsquatting") {
		t.Fatalf("hallucinated package not reported: %+v", u)
	}
	if _, bad := byComp["lodash"]; bad {
		t.Fatal("an existing package must not be reported as unknown")
	}
	if d := byComp["request"]; d.Category != "deprecated-package" || !strings.Contains(d.Description, "request has been deprecated") {
		t.Fatalf("deprecated package: %+v", d)
	}
	var stale finding.Finding
	for _, f := range res.Findings {
		if f.Category == "unmaintained-dependency" {
			stale = f
		}
	}
	// lodash last released 2021-02-20, over two years before 2026-01-01.
	if len(stale.Evidence) != 1 || !strings.Contains(stale.Evidence[0].Detail, "lodash: last release 2021-02-20") || stale.Impact.Buyer != finding.BuyerSupportCost {
		t.Fatalf("unmaintained dependency: %+v", stale)
	}
	if len(res.Findings) != 7 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	var noted bool
	for _, l := range res.Limitations {
		noted = noted || strings.Contains(l, "Go standard library was not checked")
	}
	if !noted {
		t.Fatalf("unpinned stdlib not explained: %v", res.Limitations)
	}
}

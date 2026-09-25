# capybari-analyzer-vulns

**Capybari Source Intelligence: Known Vulnerability Scanner: which dependencies have published vulnerabilities?**

Matches every dependency with an exact version (from the `dependencies` capability) against [OSV.dev](https://osv.dev). OSV aggregates GitHub Security Advisories, PyPA, the Go vulnerability database, RustSec, npm, Packagist, RubyGems, Maven, NuGet, OSS-Fuzz and malicious-package feeds.

- **One finding per package version.** All its advisories are listed in the finding, with the **lowest version that fixes all of them**: *"Upgrade lodash to 4.17.21 or later."*
- Severity comes from the CVSS v3 base score, computed locally from the vector, or from the database's own rating (for example GHSA `MODERATE`).
- **Malicious packages** (`MAL-…`) are critical and come with incident-response guidance.
- Dev-only dependencies are lowered one severity step and tagged.
- **Hallucinated-package check:** every direct dependency is looked up on [deps.dev](https://deps.dev). Packages that do not exist in their public registry (npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems) are reported. AI assistants sometimes invent plausible names, and attackers register them ("slopsquatting"). This works even without a lockfile.
- **Maintenance check (same deps.dev response, no extra requests):** direct dependencies whose latest release is **deprecated** by their maintainers are reported one by one, and those with **no release in over 2 years** in one grouped finding (low confidence: some libraries are simply finished).

| | |
|---|---|
| Requires | `dependencies` |
| Scores | Security |
| Network | **required**, `api.osv.dev` and `api.deps.dev` only (enforced) |
| What is sent | package name, ecosystem and version (OSV); direct dependency names (deps.dev). Never source code, file contents or paths |
| Offline | skipped. The report says so and recommends running online |

```bash
go run ./cmd/capybari-vulns ./path/to/project
```

## License

Apache-2.0

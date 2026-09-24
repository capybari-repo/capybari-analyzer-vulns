# capybari-analyzer-vulns

**Capybari Source Intelligence: Known Vulnerability Scanner: which dependencies have published vulnerabilities?**

Matches every dependency with an exact version (from the `dependencies` capability) against [OSV.dev](https://osv.dev). OSV aggregates GitHub Security Advisories, PyPA, the Go vulnerability database, RustSec, npm, Packagist, RubyGems, Maven, NuGet, OSS-Fuzz and malicious-package feeds.

- **One finding per package version.** All its advisories are listed in the finding, with the **lowest version that fixes all of them**: *"Upgrade lodash to 4.17.21 or later."*
- Severity comes from the CVSS v3 base score, computed locally from the vector, or from the database's own rating (for example GHSA `MODERATE`).
- **Malicious packages** (`MAL-…`) are critical and come with incident-response guidance.
- Dev-only dependencies are lowered one severity step and tagged.

| | |
|---|---|
| Requires | `dependencies` |
| Scores | Security, Dependency Health |
| Network | **required**, `api.osv.dev` only (enforced) |
| What is sent | package name, ecosystem and version. Never source code, file contents or paths |
| Offline | skipped. The report says so and recommends running online |

```bash
go run ./cmd/capybari-vulns ./path/to/project
```

## License

Apache-2.0

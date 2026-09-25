# Methodology: Known Vulnerability Scanner

## Matching

1. Collect packages with an exact version and an ecosystem. Go versions drop the `v` prefix, and the Go toolchain (`stdlib`) is normalised to `x.y.0`.
2. `POST https://api.osv.dev/v1/querybatch` in batches of 1,000, following `next_page_token`.
3. `GET /v1/vulns/{id}` for each matched advisory (up to 400 per scan, 8 in parallel). Withdrawn advisories are ignored.

## Severity

| Source | Mapping |
|---|---|
| CVSS v3.x vector | computed base score: ≥ 9.0 critical, ≥ 7.0 high, ≥ 4.0 medium, > 0 low |
| database rating (GHSA etc.) | CRITICAL/HIGH/MODERATE/LOW → critical/high/medium/low |
| none | medium, **medium confidence** |
| `MAL-` id | critical (malicious package) |
| dev-only dependency | one step lower, tagged `dev-dependency` |

A package's finding takes the severity of its most severe advisory.

## Fix version

For each advisory, the lowest `fixed` event greater than the installed version, for the matching package name. The finding recommends the highest of those, so a single upgrade clears every listed advisory.

## Unknown packages (hallucination / slopsquatting check)

For each **direct** dependency, up to 300 per scan, in npm, PyPI, Go (except `stdlib`), Maven, Cargo, NuGet and RubyGems, `GET https://api.deps.dev/v3/systems/{system}/packages/{name}` is requested. Only a **404** produces an `unknown-package` finding: **high** severity for unscoped public names (anyone can register them), **medium** for scoped npm packages, Maven coordinates and Go modules. Network errors and other statuses are ignored and noted as a limitation.

Confidence is **medium**, and **low** for scoped npm packages (`@org/…`), Maven coordinates and Go modules, which are often private. Packages from private registries or workspaces are legitimately absent, and the finding says so.

## Limitations

- Version matching does not prove the vulnerable code is reachable.
- Declared ranges without a lockfile cannot be matched.
- The OSV service must be reachable. Offline scans skip this capability.

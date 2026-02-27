# XEOL EOL database overview

This document summarizes what the XEOL (xeol-io/xeol) EOL database contains and how it is used. It is intended for implementers of the Codacy Trivy EOL scanner.

## What is in the XEOL DB

- **Source**: The open-source XEOL scanner uses an **open-source EOL data source**. The DB is hosted at `https://data.xeol.io/xeol/databases/` (listing: `listing.json`). DB archives are tar.gz files containing `xeol.db` (SQLite) and `metadata.json`.
- **Updated**: The EOL Explorer database is **updated weekly**. For Codacy we download the DB at **container build time** (offline at runtime).
- **Package ecosystems (EOL Explorer)**: The public EOL Explorer indexes:
  - **NuGet** (.NET packages)
  - **npm** (JavaScript/Node)
  - **Maven** (Java)
- **Additional coverage**: Xeol also uses **endoflife.date**-style data. endoflife.date tracks 400+ products across:
  - Programming languages (Python, Java, Node.js, PHP, Go, Ruby, etc.)
  - Databases (MongoDB, PostgreSQL, Redis, MySQL)
  - OS / distros (Windows, Android, macOS, Linux distros)
  - Frameworks (Angular, Django, Rails, .NET)
  - Server apps (Nginx, Kubernetes, Tomcat, HAProxy)
  - Cloud (EKS, GKE, AKS)
- **DB schema (v1)**:
  - **products** table: `id`, `name`, `permalink` (e.g. product name and slug).
  - **cycles** table: `product_name`, `product_permalink`, `release_cycle`, `eol` (date), `eol_bool`, `lts`, `latest_release`, `latest_release_date`, `release_date`.
- **Lookup**: The store exposes:
  - `GetCyclesByPurl(purl string)` — short PURL (e.g. `pkg:npm/lodash` without version) → list of EOL cycles for that package.
  - `GetCyclesByCpe(cpe string)` — CPE (e.g. for OS/distro) → list of EOL cycles.
- **Cycle fields used for severity**: Each cycle has `Eol` (string date, e.g. `"2025-06-01"`) and `EolBool`. We parse `Eol` and compute days until EOL to map to Codacy severity (critical / high / medium / minor).

## Libraries and packages (summary)

- **Libraries**: The DB does not list “libraries” as a separate concept; it lists **products** and **release cycles** with EOL dates. Package ecosystems covered for **application dependencies** are primarily **npm**, **NuGet**, and **Maven** (via EOL Explorer). Broader products (languages, DBs, OSes, frameworks) come from endoflife.date-style data.
- **Go API**: `github.com/xeol-io/xeol/xeol` provides `FindEol(store, d, matchers, packages, failOnEolFound, eolMatchDate)` and `LoadEolDB(cfg, update)`. The DB is SQLite; the curator downloads from `Config.ListingURL` (default `https://data.xeol.io/xeol/databases/listing.json`) and expects `DBRootDir` to contain `{schema_version}/xeol.db` and metadata.

## References

- Xeol: https://github.com/xeol-io/xeol  
- EOL Explorer: https://www.xeol.io/explorer  
- endoflife.date: https://endoflife.date  
- DB listing URL (default): `https://data.xeol.io/xeol/databases/listing.json`

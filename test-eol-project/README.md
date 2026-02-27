# Test project for EOL detection

This project pins the **protractor** npm package (v7.0.0), which is in the xeol DB as EOL (2023-08-31). It is used to verify that the codacy-trivy EOL scanner reports useful findings.

## 1. One-time setup

```bash
cd test-eol-project
npm install
cd ..
```

Install **xeol** (required for EOL scan):  
`brew install xeol-io/xeol/xeol` or [install script](https://github.com/xeol-io/xeol#installation).

## 2. Quick check that xeol finds EOL

From repo root, after `npm install` in test-eol-project:

```bash
xeol dir:./test-eol-project -o json --lookahead 365d
```

You should see matches for **protractor** (EOL 2023-08-31). This confirms xeol and its DB work.

## 3. Full tool (codacy-trivy with EOL patterns)

For a local run you do **not** need the container. You do need:

- **Trivy DB cache** – use a local cache dir so the tool can run (and on first use with that dir, it will download the DB if you have network).
- **xeol** on PATH – so the EOL scanner can find obsolete deps.

Build:

```bash
make build
GOTOOLCHAIN=auto GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -o bin/eoltest ./cmd/eoltest
```

One-time: populate Trivy cache (if you don’t have one yet):

```bash
trivy --cache-dir ./cache image --download-db-only
```

Run codacy-trivy (eoltest) against the test project:

```bash
TRIVY_CACHE_DIR=$PWD/cache ./bin/eoltest -dir ./test-eol-project
```

You should see EOL issues for the `protractor` package.

## 4. Step 5: Run in container (prove EOL in Docker)

The image bakes in the xeol EOL DB at build time. Build and run:

```bash
docker build -t codacy-trivy:eol .
docker run --rm -v "$(pwd)/test-eol-project:/project:ro" codacy-trivy:eol /dist/bin/eoltest -dir /project
```

You should see `[eol_critical] End-of-life package protractor@7.0.0 (EOL 2023-08-31)`.


# Codacy Trivy

This is the docker engine we use at Codacy to have [Trivy](https://github.com/aquasecurity/trivy) support.

> [!IMPORTANT]
> For local development, please run `go env -w GOEXPERIMENT=jsonv2`, since the current Trivy library depends on experimental go modules.

## Usage

You can create the docker by doing:

  ```bash
  docker build -t codacy-trivy:latest .
  ```

The docker is ran with the following command:

  ```bash
  docker run -it -v $srcDir:/src codacy-trivy:latest
  ```

## Generate Docs

 1. Update the version in `go.mod`
 2. Install the dependencies:

```bash
go mod download
```

 3. Run the DocGenerator:

```bash
go run ./cmd/docgen
```

## Test

We use the [codacy-plugins-test](https://github.com/codacy/codacy-plugins-test) to test our external tools integration.
You can follow the instructions there to make sure your tool is working as expected.

## Versioning

The latest version of this docker image will be updated daily with new versions of Trivy's vulnerability DBs. The update process keeps the version tag.

For example, if the latest tag is `1.2.3`, then each day the image content for that tag is updated.

If you're using this docker image please guarantee that you're always using the latest version, and that you always pull the image, to make sure you're not exposed to new vulnerabilities.

The `latest` tag is also available but you should avoid using it, as it is harder to track which version of the image is running and more difficult to roll back properly.

## Updating Trivy

After updating the Trivy version in `go.mod`, you need to update the version in [CircleCI's configuration](/.circleci/config.yml) to make sure the vulnerabilities DB downloaded are compatible.

## Agent Playbook: Updating This Repository End-to-End

This section is written for an AI coding agent (or a human) tasked with updating this repo — most commonly bumping the wrapped [Trivy](https://github.com/aquasecurity/trivy) version, but also Go dependency, CircleCI orb, or base image bumps. Follow it top to bottom.

### 1. What this repository is

This is a **Codacy engine**: a Go wrapper (`cmd/tool/main.go`, `internal/tool`, built on `codacy-engine-golang-seed/v8`) that packages [Trivy](https://github.com/aquasecurity/trivy), Aqua Security's vulnerability/secret/misconfiguration scanner, as a Docker image Codacy's platform runs against a customer's source code. Unlike engines that scrape an upstream rule catalog, this repo does **not** have a generated `docs/patterns.json` in the checked-out tree — the "patterns" here are a small, hand-authored, fixed set of Codacy categories (`secret`, `vulnerability_critical/high/medium/minor`, `malicious_packages`) declared directly in `internal/docgen/rule.go`. `patterns.json` and `docs/description/*.md` are (re)generated from that fixed list by `cmd/docgen` (`internal/docgen/docgen.go`) via `go run ./cmd/docgen`, and the Dockerfile runs this generator during the image build (`RUN ... go run ./cmd/docgen`) — it is not something you need to run and commit separately unless you change `internal/docgen/rule.go` itself. `docs/tool-description.md` and `docs/description/*.md` are checked into git and should stay in sync with `internal/docgen/rule.go` if that file changes. `docs/multiple-tests/*` (fixture `src/`, `patterns.xml`, `results.xml`) are fixtures consumed by `codacy-plugins-test`; a Trivy version bump commonly changes vulnerability DB contents and requires regenerating `results.xml` via `scripts/regenerate_fixtures.py` (see prior commit `a9ec845`, "chore: regenerate fixture results for Trivy DB update").

### 2. Files that encode versions — check all of these on every update

| File | What it controls | What to check |
|---|---|---|
| `go.mod` → `github.com/aquasecurity/trivy` | The Trivy library version vendored into the Go build (has an inline comment: `// Also update .circle/config.yml`) | Bump to the target version; run `go mod tidy`/`go build` to update `go.sum` and transitive deps. |
| `.circleci/config.yml` → `install_trivy_and_download_dbs` reference (`curl ... install.sh | sh -s -- -b . v0.X.Y`) | The standalone Trivy CLI binary CircleCI installs to pre-download vulnerability DBs into the Docker build cache | Must match the `go.mod` version exactly (same Trivy release, DB compatibility). |
| `.circleci/config.yml` → `build_and_publish_docker` reference (`--build-arg TRIVY_VERSION=0.X.Y`) | The `TRIVY_VERSION` build arg baked into the image (used for the tool's reported version) | Same value as the other two. |
| `.circleci/config.yml` → `codacy: codacy/base@X.Y.Z` orb | Shared CircleCI steps (checkout, docker publish, tag, ECR mirror) | Check the latest published version; not required every bump, but was bumped alongside Trivy in `8d886e7`. |
| `.circleci/config.yml` → `codacy_plugins_test: codacy/plugins-test@X.Y.Z` orb | Runs `codacy-plugins-test` in CI | Same as above. |
| `Dockerfile` → `FROM golang:1.25-alpine` | Go toolchain the image is built with | Only bump if the target Trivy/Go version requires a newer Go. |
| `go.mod` → `go 1.25.8` line | Go language version | Keep in sync with the Dockerfile's `golang:` base image tag. |

The prior real bump commit `8d886e7` ("bump: Trivy to 0.69.2 (#246)") touched exactly `go.mod`, `go.sum`, and both Trivy references in `.circleci/config.yml` — use it as a template for the diff shape.

### 3. Step-by-step update procedure

1. **Bump the Trivy version** in `go.mod` (the `require github.com/aquasecurity/trivy` line), then run `go mod tidy` (or `go get github.com/aquasecurity/trivy@vX.Y.Z && go mod tidy`) to refresh `go.sum` and any transitive dependency bumps that come along with it. Confirm a matching upstream `vX.Y.Z` tag exists at https://github.com/aquasecurity/trivy/releases.
2. **Update `.circleci/config.yml`** in both places noted above (the `install.sh ... v0.X.Y` line and the `--build-arg TRIVY_VERSION=0.X.Y` line) so they match `go.mod` exactly.
3. **Set the GOEXPERIMENT flag** (`go env -w GOEXPERIMENT=jsonv2`) — the Trivy library currently depends on it for local builds, per the README warning at the top of this file.
4. **Compile and test locally**: `go generate ./... && go test ./...` (mirrors the CircleCI `generate_and_test` job).
5. **Regenerate docs if `internal/docgen/rule.go` changed**: `go run ./cmd/docgen` (writes `docs/patterns.json` and `docs/description/*`); if you only bumped the Trivy version, this step is not required since the pattern list is version-independent.
6. **Build the Docker image** with the matching build arg: `docker build --build-arg TRIVY_VERSION=X.Y.Z -t codacy-trivy:latest .`
7. **Regenerate test fixtures if vulnerability results changed**: a Trivy/DB bump can change which vulnerabilities are detected in the `docs/multiple-tests/*` fixtures. Run `scripts/regenerate_fixtures.py` (see commit `a9ec845` for the expected diff shape — it only touches `docs/multiple-tests/*/results.xml`) and review the diff for real behavior changes vs. noise.
8. **Run `codacy-plugins-test` locally** before pushing — clone https://github.com/codacy/codacy-plugins-test and run its DockerTest commands (single and multiple-test modes, mirroring the CircleCI `plugins_test` job which runs with `run_multiple_tests: true`) against your local image tag.
9. **Iterate on failures**, re-running only the relevant command after each fix.
10. **Commit** the version bump(s), regenerated fixtures, and any regenerated docs together in one change (only touch files that actually need to change for this bump).
11. **Push and open a PR** against `master` (the default branch).
12. **Poll the PR's real CI checks until they all pass — local validation is NOT the finish line.** After every push, run `gh pr checks <pr-url>` and keep re-polling (short sleep while any check is `pending`) until all checks finish. If a check fails, fetch its actual log (don't guess), find the true root cause, fix it, push again (never `--no-verify`, never force-push), and re-poll. Repeat until every check is green. **The CI environment's toolchain can differ from your local one** (CircleCI installs its own standalone Trivy CLI and downloads fresh DBs), so a clean local run does not guarantee CI passes. Only stop iterating when every check passes, or you hit a genuine product/infra decision that needs a human.

### 4. Common failure modes and fixes

| Symptom | Cause | Fix |
|---|---|---|
| CI fails downloading vulnerability DBs, or `plugins_test` reports mismatched vulnerability results | The standalone Trivy CLI version installed by `.circleci/config.yml`'s `install_trivy_and_download_dbs` step is out of sync with the `go.mod` library version, or the vulnerability DB itself changed | Ensure both `.circleci/config.yml` Trivy references and `go.mod` use the exact same version; regenerate `docs/multiple-tests/*/results.xml` via `scripts/regenerate_fixtures.py`. |
| Local build fails with errors about experimental JSON handling | `GOEXPERIMENT=jsonv2` not set | Run `go env -w GOEXPERIMENT=jsonv2` before building/testing, as the Dockerfile and CircleCI config both do. |

### 5. Definition of done

- Trivy version bumped consistently in `go.mod` (with `go.sum` refreshed) and both places in `.circleci/config.yml`.
- Any CircleCI orb bumps (`codacy/base`, `codacy/plugins-test`) applied if relevant.
- `go generate ./... && go test ./...` pass locally.
- Docker image builds successfully with the matching `TRIVY_VERSION` build arg.
- `docs/multiple-tests/*/results.xml` fixtures regenerated and reviewed if vulnerability detection results changed.
- `docs/patterns.json` / `docs/description/*` regenerated only if `internal/docgen/rule.go` changed.
- `codacy-plugins-test` commands pass locally against the freshly built image.
- **After pushing and opening/updating the PR, every CI check on it is green.** Poll `gh pr checks <pr-url>` and iterate on any failure until all pass.

## What is Codacy?

[Codacy](https://www.codacy.com/) is an Automated Code Review Tool that monitors your technical debt, helps you improve your code quality, teaches best practices to your developers, and helps you save time in Code Reviews.

### Among Codacy’s features

- Identify new Static Analysis issues
- Commit and Pull Request Analysis with GitHub, BitBucket/Stash, GitLab (and also direct git repositories)
- Auto-comments on Commits and Pull Requests
- Integrations with Slack, HipChat, Jira, YouTrack
- Track issues in Code Style, Security, Error Proneness, Performance, Unused Code and other categories

Codacy also helps keep track of Code Coverage, Code Duplication, and Code Complexity.

Codacy supports PHP, Python, Ruby, Java, JavaScript, and Scala, among others.

### Free for Open Source

Codacy is free for Open Source projects.

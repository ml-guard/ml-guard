# Publishing the GitHub Action to Marketplace

ML Guard ships two pieces of CI tooling:

1. The `mlsupplychain` PyPI package itself (this repo, `ml_guard/cli.py`).
2. A thin GitHub Action wrapper called `ml-guard/scan-action` which
   `pip install`s mlsupplychain and runs `ml-guard scan` with the inputs the
   workflow author configured.

**The Action lives in a separate repo** (`ml-guard/scan-action`) because
GitHub Marketplace requires `action.yml` at the repo root, and our main
repo is the Python package.

## Set-up (one-time)

1. Create a public repo `ml-guard/scan-action`.
2. Copy `.github/actions/scan/action.yml` from this repo to its root
   (rename → just `action.yml`).
3. Add a `README.md` that mirrors the action's `description` plus a
   small usage example (see template below).
4. Add a release `v1.0.0` tag plus a moving `v1` tag that always points
   to the latest 1.x release. The Marketplace listing requires both.
5. On the repo's main page, click **Draft a release** and check
   **Publish this Action to the GitHub Marketplace**. Pick a category
   (`Continuous integration` and `Security` both fit).

## Promotion

After the first release, link to the Marketplace page from:

- This project's README (`pip install` quickstart section)
- `docs/examples/github-workflow.yml`
- The PyPI project description (in `pyproject.toml -> [project] readme`)

## Template README for `ml-guard/scan-action`

```markdown
# ML Guard Security Scan

Drop-in GitHub Action that scans your repo for ML supply-chain risks:
malicious pickles, leaked secrets, ONNX with custom ops, vulnerable
dependencies. Powered by [ml-guard](https://github.com/ml-guard/ml-guard).

## Usage

```yaml
- uses: ml-guard/scan-action@v1
  with:
    path: ./models
    fail-on: critical
    format: sarif
    output: ml-guard.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ml-guard.sarif
```

See <https://github.com/ml-guard/ml-guard#readme> for full docs.
```

## Versioning policy for the Action

- `v1.x.y` follows the `ml-guard` major version. Minor/patch bumps
  inside `v1` are non-breaking.
- The moving `v1` tag advances on every `1.x.y` release. Users who
  pin to `@v1` get patches automatically; users who pin to `@v1.2.3`
  stay on that exact version.
- When ml-guard hits `2.0.0`, a new `ml-guard/scan-action` repo or
  major-tag is created. Old repos stay live for migration.

## Updating the Action

When CLI flags change in ml-guard:

1. Sync the changes from `.github/actions/scan/action.yml` (this repo)
   into `ml-guard/scan-action`.
2. Bump the version in `scan-action`.
3. Move the `v1` tag.
4. Note the change in `scan-action`'s `CHANGELOG.md`.

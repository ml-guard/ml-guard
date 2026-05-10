# Releasing ML Guard

This is for maintainers. Public users don't need to read this.

## Prerequisites (one-time)

1. **PyPI Trusted Publisher** for `ml-guard`:
   - Go to <https://pypi.org/manage/project/mlsupplychain/settings/publishing/>
   - Add publisher: GitHub, owner=`ml-guard`, repo=`ml-guard`,
     workflow=`release.yml`, environment=`pypi`.
   - Repeat with environment=`testpypi` on test.pypi.org for previews.

2. **GitHub environments**: in the repo settings, create environments
   `pypi` and `testpypi` (no extra secrets needed — Trusted Publisher
   handles auth via OIDC).

3. **Branch protection**: require CI to pass on `main`, and require
   pull-request review for all merges.

## Release steps

1. **Bump version** in `pyproject.toml` and the matching string in
   `ml_guard/__init__.py`. Use semver:
   - patch (`0.1.0 → 0.1.1`) — bug fixes only, no new findings or
     CLI changes.
   - minor (`0.1.0 → 0.2.0`) — new scanner, new rule, new CLI
     command, breaking *internal* API.
   - major (`0.1.0 → 1.0.0`) — breaking change to `rule_id`s, exit
     codes, or output formats.

2. **Update `CHANGELOG.md`**:
   - Move `[Unreleased]` items into a new `[X.Y.Z] - YYYY-MM-DD` section.
   - Open a new empty `[Unreleased]` block at the top.

3. **Run pre-release smoke**:
   ```bash
   python -m build
   python -m twine check dist/*
   pip install dist/ml_guard-*.whl
   ml-guard --version
   ml-guard scan ./tests/fixtures   # should run without errors
   ```

4. **Tag and push**:
   ```bash
   git tag -s v0.X.Y -m "Release v0.X.Y"
   git push origin v0.X.Y
   ```
   The `release.yml` workflow:
   - Refreshes the bundled mini OSV DB from upstream
   - Builds sdist + wheel
   - Publishes to PyPI via Trusted Publisher
   - Creates a GitHub Release with `SHA256SUMS.txt`

5. **TestPyPI dry-run** (optional, recommended before majors):
   - Trigger `release.yml` manually from the Actions tab with
     `target=testpypi`.
   - Test install: `pip install -i https://test.pypi.org/simple/ mlsupplychain`.

6. **Post-release**:
   - Verify the release on <https://pypi.org/project/mlsupplychain/>.
   - Verify the GitHub Action Marketplace page if you ship the
     scan-action update.
   - Tweet / post wherever the project announces.

## Hotfix procedure

For a critical CVE in ml-guard itself (false negative in the pickle
scanner, parser crash on adversarial input, etc.):

1. Branch `fix/CVE-...` from the most recent release tag.
2. Patch + test + bump to next patch version.
3. Tag and push as a normal release; the workflow handles the rest.
4. File a security advisory on GitHub with the CVE details.

## Yanking a bad release

If a release contains a regression:

```bash
# This marks it on PyPI as "yanked" — pip won't install unless the user
# explicitly requests that exact version.
twine yank ml-guard==0.X.Y --reason "Brief description of the issue"
```

Then immediately cut a fixed `0.X.Y+1`.

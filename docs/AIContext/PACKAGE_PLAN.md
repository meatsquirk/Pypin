# DCPP Python Packaging Plan (No Implementation Yet)

## Goal
Convert the repo from a project-only layout into a publishable Python package (pip install), and make `torf` a required dependency.

## Scope
Plan only. No code or config changes applied in this phase.

---

## Phase 1 — Packaging Requirements & Decisions
1. **Define package target**
   - Decide package name (keep `dcpp-python` or publish under a new PyPI name).
   - Decide supported Python versions for release policy.
   - Decide release cadence and versioning scheme (SemVer or date-based).

2. **Make torf required**
   - Plan to move `torf>=4.0.0` from optional extras into core dependencies.
   - Decide if any “local-only” BitTorrent mode remains; document consequences.

3. **Clarify optional vs required dependencies**
   - Identify which features are optional (libp2p, discovery, HTTP API) and which are core.
   - Decide if `libp2p` remains optional or becomes required for “network mode”.

---

## Phase 2 — Packaging Structure & Metadata
1. **Pyproject metadata**
   - Verify `project.name`, `version`, `description`, `license`, `authors`.
   - Ensure `project.urls` are accurate for the published package.
   - Add `classifiers` for status, audience, license, and Python versions.

2. **Dependencies**
   - Add `torf>=4.0.0` to `[project].dependencies`.
   - Keep extras for `dev`, `p2p`, `discovery` (unless changed in Phase 1).

3. **Build system**
   - Confirm `build-system` uses `setuptools.build_meta` and is compatible with PyPI.
   - Decide if `setuptools_scm` or manual versioning is used.

---

## Phase 3 — Distribution & Install Experience
1. **Package layout**
   - Ensure `src/dcpp_python/` is the only package included.
   - Ensure tests are excluded from the wheel unless explicitly desired.

2. **Runtime entry points**
   - Verify `project.scripts` (`dcpp-client`, `dcpp-daemon`) work in an installed context.

3. **README updates for pip users**
   - Add install instructions: `pip install <package>`.
   - Explain BitTorrent requirements (torf required).
   - Provide minimal examples runnable after install.

---

## Phase 4 — Release Process & CI
1. **Build verification**
   - Add a packaging test: build sdist/wheel and install in a clean env.

2. **CI publishing strategy**
   - Decide on GitHub Actions (or similar) for tagging and PyPI publish.
   - Add test matrix and packaging checks.

3. **Artifact validation**
   - Verify package import and CLI entry points from the wheel.
   - Optionally add `twine check` to release workflow.

---

## Phase 5 — Backward Compatibility & Migration Notes
1. **Migration notes**
   - Document that `torf` is now required.
   - Document any breaking changes to dependency extras.

2. **Deprecations**
   - If any environment variables or flags change, list them clearly.

---

## Deliverables (When Implemented)
- `pyproject.toml` updated with `torf` in core deps and any metadata changes.
- README updated with pip‑first install instructions.
- CI packaging pipeline (build/test/publish).
- Release checklist for maintainers.

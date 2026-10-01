---
paths:
  - ".github/**"
  - "action.yml"
  - "examples/**"
---

# GitHub Actions hardening

Load the `iace-ci-cd` skill before changing workflows or the action.

- Pin every action to a full commit SHA with a version comment. Resolve SHAs with `gh api`, never from memory.
- Use top-level `permissions: contents: read`, and grant extra permissions per job only.
- Use `actions/checkout` with `persist-credentials: false`. Never use `pull_request_target` with PR code.
- Never interpolate `${{ github.event.* }}` into `run:`. Pass values through `env:` and quote them.
- Set `timeout-minutes` on every job. `actionlint` must pass.

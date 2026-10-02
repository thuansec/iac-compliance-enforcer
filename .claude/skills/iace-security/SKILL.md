---
name: iace-security
description: Secure development rules and threat model for iac-compliance-enforcer (iace), a security tool that reads untrusted Terraform from pull requests — trust boundaries, fail-closed principles, no code execution from scanned repos, offline-by-default networking, safe filesystem and archive handling, resource limits, secret handling and redaction, supply-chain controls (pinned deps and actions, govulncheck, signed releases and policy bundles, licenses), AI data protection, and a per-change security review checklist. Use this whenever code touches files, archives, network, processes, secrets, config trust, CI workflows or dependencies, and before marking any task done.
---

# Security for a security tool

iace is pointed at **untrusted pull requests**, often in CI next to tokens. A bug that executes
scanned code, leaks a secret, or reports "compliant" by mistake is a security incident, not a
cosmetic defect. Full threat model: [references/threat-model.md](references/threat-model.md).

## Trust boundaries
| input | trust | why |
|---|---|---|
| Terraform files, tfvars, `.terraform/modules` in the scanned repo | **untrusted** | written by PR authors |
| `.iace.yaml` in the scanned repo | **untrusted** (but reviewed via CODEOWNERS) | PR authors can edit it |
| org baseline, `--trusted-key`, CI env | trusted | supplied by the workflow owner |
| policy bundles | untrusted until digest **and** signature verify | supply chain |
| AI model output | untrusted | may be steered by injected text |
| the iace binary and built-in policies | trusted when release signature and provenance verify | |

## Principles
1. **No execution of scanned content.** Never run `terraform`, providers, modules, hooks or
   scripts from the scanned repo. If iace ever runs a subprocess (only `git` for an optional
   source), use `exec.CommandContext` with a fixed binary and an args slice (no shell), a minimal
   env (`GIT_TERMINAL_PROMPT=0`, no inherited credentials), and a timeout.
2. **Fail closed.** Any error in parsing, config, policy, verification or evaluation → exit 2.
   Unknowns and skipped areas are reported as coverage gaps. Nothing defaults to "pass".
3. **Offline by default.** A scan makes zero network calls unless remote bundles or AI are
   configured. Then use HTTPS only, allowlisted hosts, timeouts, size caps, and no credentials
   on redirects.
4. **Least data.** Logs, reports and prompts never contain secret values (see redaction rules in
   `iace-reporting` and `iace-ai-remediation`).
5. **Bounded resources.** Every input has limits: file size, file count, module depth, expansion
   count, string size, bundle size and file count, config size, evaluation time. Hitting a limit is a
   reported gap or error, never a crash or hang.

## Secure coding rules (Go)
- **Filesystem**: all scanned-content access goes through `internal/fsutil` on `os.Root`, which
  prevents `..` and symlink escapes. It rejects non-regular files and caps reads with `io.LimitReader`.
  Config-supplied paths (module sources, `paths`, `--var-file`) are relative and validated.
- **Archives** (bundles): reject absolute paths, `..`, symlinks/hardlinks, device files,
  duplicates and too many entries, and cap the total uncompressed size (decompression bombs).
- **Parsing**: YAML strict with no anchors; JSON with size caps; HCL with recursion and expression
  caps. Regexes are Go RE2 (no ReDoS), compiled once.
- **HTTP**: a custom `http.Client` with timeouts, TLS ≥ 1.2, never `InsecureSkipVerify`,
  `CheckRedirect` limiting hops and stripping `Authorization` on host change, and response bodies
  capped and closed.
- **Crypto**: sha256 for digests, compared as fixed-length hex. Policy-bundle signatures are
  detached ECDSA P-256 signatures over the whole tarball, checked with `ecdsa.VerifyASN1` before
  the bundle is parsed. `crypto/rand` for anything secret, and never `math/rand` for security.
- **Output files**: atomic writes. Reports 0644; caches and anything with AI data 0600 inside 0700 dirs.
- **Errors and logs**: never include attribute values, tokens, prompts or response bodies.
  At debug level, log sizes and hashes instead.

## Harness guardrails (deterministic, tested)
The development loop itself runs behind hooks in `.claude/settings.json`, tested by
`.claude/hooks/tests/run.sh` (also run by the gates):
- `block-secrets.sh` (PreToolUse Bash) blocks commands containing credential formats, and fails
  closed without `jq`.
- `guard-loop.py` (PreToolUse Bash, Write, Edit) enforces `.claude/loop-policy.json`:
  - No commits or pushes to `main`. Feature branches are pushed only after the full gates passed on
    their exact content.
  - Merges only for green, up-to-date, conflict-free PRs (squash, pinned head, never `--admin`).
  - Blocks force pushes, destructive git commands, `sudo`, downloads piped into a shell,
    terraform apply/destroy, and GitHub state changes.
  - Asks a human before anything edits the harness (`.claude/**`, `CLAUDE.md`), so the loop
    cannot loosen its own policy, hooks or instructions.
- `format-file.sh` (PostToolUse Write|Edit) formats Go, Rego and Terraform. It is best effort.
- `permissions.deny` repeats the most destructive cases as a second layer.
Treat a block as a signal, never an obstacle to route around.

## Secrets in this repository and the loop
- Never commit real credentials. Fixtures use obviously fake values. The project's
  `block-secrets.sh` hook rejects shell commands containing key-like strings, so create fixture
  files with the Write tool rather than `echo`ing secrets in Bash.
- Tokens for CI come from GitHub secrets or OIDC. Never print them, and never pass them via
  command-line args (visible in process lists).

## Supply chain
- `go.sum` committed; `go mod verify` and `govulncheck ./...` in gates and CI; Dependabot for
  gomod and actions; dependency license allowlist (`iace-go-standards`); never import or copy
  Terraform core (BUSL-1.1).
- Actions pinned by full SHA; least-privilege `permissions`; no `pull_request_target` with PR
  code (`iace-ci-cd`).
- Releases: reproducible builds, checksums, SBOM, cosign keyless signatures, build provenance
  attestations. Policy bundles are signed with a non-exportable AWS KMS key that only the tag-triggered policy
  release workflow can use (D-03, `iace-repo-policy`).

## Security review checklist (run on every diff before commit)
- [ ] New input paths are validated, confined to the root, and size-limited.
- [ ] No new subprocess, or it uses a fixed binary, args slice, minimal env and timeout.
- [ ] No new network call, or it is opt-in, allowlisted, time- and size-limited, and credentials stay on their host.
- [ ] Every error path fails closed (exit 2) and is tested.
- [ ] No secret value can reach logs, reports, caches or prompts. A test proves it for new outputs.
- [ ] New limits have tests at, just below and just above the limit.
- [ ] Trust boundary respected: nothing from repo config or bundles is treated as trusted.
- [ ] Dependencies: license allowed, maintained, govulncheck clean.
- [ ] Workflows: pinned SHAs, minimal permissions, no untrusted interpolation in `run:`.
- [ ] Threat model updated if a boundary, asset or mitigation changed.

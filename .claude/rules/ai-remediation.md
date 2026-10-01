---
paths:
  - "internal/remediation/**"
  - "schemas/ai-fix*.json"
---

# AI fix suggestions

Load the `iace-ai-remediation` skill, and the built-in `claude-api` skill for SDK code.

- AI output is advisory and untrusted. It never changes pass/fail, and only validator-verified fixes are shown by default.
- Redact secrets before anything leaves the process. Send minimal excerpts, never tfvars, state or whole files.
- Tests use fakes or `httptest` only. Live API calls require `live_api_calls: yes` in the BACKLOG loop settings.
- Never guess SDK names: confirm them with `go doc` or the claude-api skill, and let the compiler check.

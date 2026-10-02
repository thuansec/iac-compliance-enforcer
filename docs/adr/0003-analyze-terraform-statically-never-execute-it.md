# 0003 · Analyze Terraform statically and never execute it

- Status: accepted
- Date: 2026-10-02
- Task: T-0005

## Context
iace's main job is gating pull requests, so it reads Terraform written by people who may not be
trusted. Running Terraform on that code executes it: `terraform init` downloads arbitrary
providers and modules, `terraform plan` runs them with whatever credentials the CI job holds,
and external data sources and provisioners can run commands. A compliance gate has to be safe to
point at a malicious pull request, run without cloud credentials, and work offline.

## Decision
By default iace parses `.tf` and `.tf.json` files with hashicorp/hcl/v2 and evaluates them
statically: variables, locals, a curated set of pure functions, `count`, `for_each`, dynamic
blocks and local modules. Anything it cannot know is recorded as unknown and reported as a
coverage gap, never treated as compliant. iace never runs `terraform`, providers, provisioners
or module code from a scanned repository, and never downloads remote modules. Plan JSON is an
opt-in input (M9) for pipelines that produced the plan in a trusted job; iace only reads it.

## Alternatives considered
- Always run `terraform plan`: the most precise values, but it executes untrusted code, needs
  credentials and network access, and is slow.
- Regex or line-based scanning: safe, but too imprecise for real modules, variables and
  expressions.

## Consequences
- Positive: safe on untrusted pull requests; no credentials, no network, fast.
- Negative / accepted risks: values known only at apply time stay unknown, so some rules report
  coverage gaps instead of findings; remote modules are not followed.
- Follow-ups: T-0101 to T-0105 implement the static loader; T-0901 to T-0904 add plan JSON.

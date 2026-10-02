# The single source of commands for humans, the loop (gates.sh) and CI. The contract for these
# targets lives in the iace-quality-gates skill. Dev tools are pinned one module per tool
# (tools/<tool>/go.mod, decision D-07) and run with `go tool -modfile=...`.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-print-directory
.DEFAULT_GOAL := help

GO ?= go
TOOLS := golangci-lint govulncheck actionlint regal opa
COVERAGE_MIN := 80
tool = $(GO) tool -modfile=tools/$(1)/go.mod $(1)

.PHONY: help ci fmt-check lint test cover-check policy-check policy-test vuln build tidy-check fmt tools

help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-13s %s\n", $$1, $$2}'

ci: fmt-check lint test cover-check policy-check policy-test vuln build tidy-check ## every check CI runs, in order

fmt-check: ## fail on Go, Rego or Terraform formatting differences
	@out=$$($(call tool,golangci-lint) fmt --diff) || { echo "$$out"; exit 1; }; \
	  if [[ -n "$$out" ]]; then echo "$$out"; exit 1; fi
	@if [[ -d policies ]]; then $(call tool,opa) fmt --list --fail policies; \
	  else echo "fmt-check: no policies/ yet, opa fmt skipped"; fi
	@if [[ ! -d testdata ]]; then echo "fmt-check: no testdata/ yet, terraform fmt skipped"; \
	  elif command -v terraform >/dev/null; then terraform fmt -check -recursive testdata; \
	  else echo "fmt-check: terraform not installed, terraform fmt skipped"; fi

lint: ## golangci-lint, regal (policies) and actionlint (workflows)
	$(call tool,golangci-lint) run
	@if [[ -d policies ]]; then $(call tool,regal) lint policies; \
	  else echo "lint: no policies/ yet, regal skipped"; fi
	@if compgen -G '.github/workflows/*.y*ml' >/dev/null; then $(call tool,actionlint); \
	  else echo "lint: no workflows, actionlint skipped"; fi

test: ## race-enabled, shuffled tests with a coverage profile
	$(GO) test -race -shuffle=on -count=1 -coverprofile=coverage.out ./...

cover-check: ## overall Go coverage from coverage.out must be at least COVERAGE_MIN
	@[[ -f coverage.out ]] || { echo "cover-check: coverage.out is missing; run make test first"; exit 1; }
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub(/%/, "", $$3); print $$3}'); \
	  [[ -n "$$total" ]] || { echo "cover-check: no total in coverage.out"; exit 1; }; \
	  awk -v t="$$total" -v min=$(COVERAGE_MIN) 'BEGIN { \
	    if (t + 0 < min + 0) { printf "cover-check: %.1f%% is below %d%%\n", t, min; exit 1 } \
	    printf "cover-check: %.1f%% (minimum %d%%)\n", t, min }'

policy-check: ## strict compile of the policies with the restricted capabilities
	@if [[ -d policies ]]; then $(call tool,opa) check --strict --capabilities policies/capabilities.json policies; \
	  else echo "policy-check: no policies/ yet (M2)"; fi

policy-test: ## Rego unit tests with at least 90% coverage
	@if [[ -d policies ]]; then $(call tool,opa) test --capabilities policies/capabilities.json --coverage --threshold 90 policies; \
	  else echo "policy-test: no policies/ yet (M2)"; fi

vuln: ## known vulnerabilities in reachable code
	$(call tool,govulncheck) ./...

build: ## static, reproducible build of every package
	CGO_ENABLED=0 $(GO) build -trimpath ./...

tidy-check: ## go.mod and go.sum are tidy, for the product and every tool module
	$(GO) mod tidy -diff
	@for t in $(TOOLS); do $(GO) -C tools/$$t mod tidy -diff || { echo "tidy-check: tools/$$t is not tidy"; exit 1; }; done

fmt: ## apply Go formatting (gofumpt, goimports)
	$(call tool,golangci-lint) fmt

tools: ## download and build the pinned tools, so the other targets work offline
	@for t in $(TOOLS); do echo "tools: $$t"; \
	  $(GO) -C tools/$$t mod download && $(GO) -C tools/$$t build -o /dev/null tool || { echo "tools: $$t failed"; exit 1; }; done

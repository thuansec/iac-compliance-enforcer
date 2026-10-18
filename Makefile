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

.PHONY: help ci fmt-check lint test cover-check policy-check policy-test vuln build tidy-check fmt tools capabilities

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

# Tests that measure the process's live heap run alone and without -race: they test memory, not
# concurrency, and under the race detector their forced collections took about two minutes,
# which pushed the package past go test's 10-minute timeout (T-0125).
# Tests that time math/big number formatting against the work calibration run there too: the
# race detector slows that formatting about 25 times (157 ms → 3.8 s), past raceSlowdown, and
# the three took about 190 s under -race (T-0124b).
# The set-sort tests of ADR 0047 time single-threaded sorts of math/big fractions in the same way:
# under -race the four took about 80 s, which pushed the package past the timeout on CI (T-0124e).
# Two sequential tests spend their time in hcl's lexer and cty's set sorting, which the race
# detector slows about 20 times with nothing concurrent to check: lexing three 1 MiB files to
# exhaust the scan-wide parse budget (136 s under -race, 6.5 s without) and converting sets of
# colliding values (77 s under -race) (T-0125).
NONRACE_TESTS := ^(TestParseMemoryPerFile|TestKeptHeapPerBudgetToken|TestNumberFormattingInDefaultsIsCharged|TestRepeatedNumberFormattingIsBounded|TestAcceptedNumberConversionsAreFast|TestMarkFunctionChainsAreBounded|TestFirstSortOfAFractionSetIsBounded|TestFractionSetPassedToModuleInstancesIsBounded|TestAcceptedModuleArgumentsSpendTheirSorts|TestIntegerSetWalksAreAccepted|TestEvaluateRootsCreatesABudget|TestConversionsIntoSetsAreBounded)$$

# go test stops a package at 10 minutes; make test warns when a race-enabled package passes this
# many seconds, so the margin is watched rather than found by a timeout (T-0125).
TEST_WATCH_SECONDS := 360

test: ## race-enabled, shuffled tests with a coverage profile, then the CPU-bound timing tests in NONRACE_TESTS without -race
	@mkdir -p .cache
	$(GO) test -race -shuffle=on -count=1 -skip '$(NONRACE_TESTS)' -coverprofile=coverage.out ./... | tee .cache/test-race.out
	@scripts/test-time-watch.sh .cache/test-race.out $(TEST_WATCH_SECONDS)
	$(GO) test -count=1 -v -run '$(NONRACE_TESTS)' ./internal/terraform/

cover-check: ## overall Go coverage from coverage.out must be at least COVERAGE_MIN
	@[[ -f coverage.out ]] || { echo "cover-check: coverage.out is missing; run make test first"; exit 1; }
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub(/%/, "", $$3); print $$3}'); \
	  [[ -n "$$total" ]] || { echo "cover-check: no total in coverage.out"; exit 1; }; \
	  awk -v t="$$total" -v min=$(COVERAGE_MIN) 'BEGIN { \
	    if (t + 0 < min + 0) { printf "cover-check: %.1f%% is below %d%%\n", t, min; exit 1 } \
	    printf "cover-check: %.1f%% (minimum %d%%)\n", t, min }'

# Builtins policies must not call: network, host and non-deterministic ones (net.cidr_* stay,
# they are pure CIDR math). The file is also an allowlist: builtins added by later OPA releases
# appear only when someone runs make capabilities and reviews the diff (iace-opa-engine).
CAPABILITIES_DENY := ["http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns", "rand.intn", "uuid.rfc4122"]

capabilities: ## regenerate policies/capabilities.json from the pinned OPA, minus the denylist
	$(call tool,opa) capabilities --current | $(call tool,opa) eval --stdin-input --format=raw \
	  'json.marshal_with_options(object.union(input, {"builtins": [b | some b in input.builtins; not b.name in $(CAPABILITIES_DENY)], "allow_net": []}), {"pretty": true, "indent": " "})' \
	  > policies/capabilities.json.tmp && mv policies/capabilities.json.tmp policies/capabilities.json

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

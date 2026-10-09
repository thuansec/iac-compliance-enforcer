# 0016 · Lower the per-file size limit to 1 MiB

- Status: accepted
- Date: 2026-10-09
- Task: T-0111a

## Context
Discovery accepted Terraform files up to 5 MiB. The nesting guard lexes each file into a token
slice before parsing, hclsyntax lexes it again and keeps a syntax tree whose nodes are much larger
than the source, and both return a diagnostic per problem. TestParseMemoryPerFile measures the
live heap, diagnostics included, of worst-case files at the limit:

| shape | lexer at 1 MiB | parse at 1 MiB | lexer at 5 MiB | parse at 5 MiB |
|---|---|---|---|---|
| distinct `aN=1` lines | 48 MB | 47 MB | 229 MB | 222 MB |
| one long list `[1,1,...]` | 117 MB | 84 MB | 560 MB | 421 MB |
| duplicate `a=1` lines | 117 MB | 144 MB | | |
| unary chain `1+-1+-1...` | 117 MB | 141 MB | | |
| empty blocks `b{}` | 117 MB | 130 MB | | |
| invalid characters `@@@...` | 286 MB | 168 MB | | |
| JSON list | (byte scan) | 80 MB | | 401 MB |

A 5 MiB file could hold over 500 MB while lexed and over 400 MB once parsed, half of the 1 GiB
scan budget, and a few such files exceed it. In total allocations, which is what the T-0102b
review measured, the 5 MiB figures were about 2 to 4 GB.

iace also kept every diagnostic that parsing a file gave: a 1 MiB file of invalid characters kept
1,048,577 of them (118 MB), one of empty unsupported blocks 262,143 (45 MB), and one of top-level
arguments 115,968 (20 MB). Each would list hundreds of thousands of lines in every report.

## Decision
- The default MaxFileSize is 1 MiB. A larger Terraform file is skipped with a too_large entry,
  which T-0109 reports as a coverage gap, so `--fail-on-gaps` catches it.
- The guard keeps lexing into a token slice. At 1 MiB that holds at most 286 MB (the error-flood
  shape), released before parsing. The guard reuses hcl's own tokenization, so iace keeps one
  definition of the syntax.
- Parsing keeps at most 100 diagnostics per file, then one too_many_diagnostics diagnostic, which
  is an error once any dropped one is. This applies to hcl's syntax diagnostics and iace's
  unsupported blocks and arguments, for Terraform files and for tfvars files (their syntax,
  undeclared variables and value diagnostics), all through parseDiag. Evaluation diagnostics are not counted: they are bounded by the
  expressions evaluated, and one expression evaluated twice must not trigger the cap.
- TestParseMemoryPerFile asserts at most 320 MB for lexing and 192 MB for parsing on the worst
  shapes at the limit.
- The memory that parsed trees keep across files, modules and roots is bounded separately
  (T-0111b).

## Alternatives considered
- A streaming nesting scanner with no token slice: it would duplicate hcl's lexer (strings,
  heredocs, template sequences), and hclsyntax lexes the file again while it parses anyway.
- A per-file token cap in place of a byte cap: more precise for sparse files, but it needs the
  token slice first. A byte cap stops large files before anything is read.
- 512 KiB: halves the transient peak, but skips more real generated files. The per-file peak
  at 1 MiB fits the budget when one file is parsed at a time.

## Consequences
- Positive: parsing one file holds at most about 450 MB transiently. That is the error-flood
  shape: hclsyntax's own tokens (286 MB) plus the tree it builds (168 MB), while ParseConfig
  runs. A parsed file keeps at most about 170 MB, and a typical file far less (realistic HCL is
  about 22 MB per MiB).
- Negative / accepted risks:
  - Generated files over 1 MiB (for example CDKTF's `.tf.json` stacks) are skipped and reported.
    Limits can be raised by the pipeline in a later task, at its own memory cost.
  - `--var-file` and automatic tfvars files are read with the same 1 MiB limit. An oversized
    tfvars file is a read error, so the scan exits 2 (fail closed) rather than reporting a gap.
  - T-0111b must leave room for one file's transient peak when it bounds the trees a scan keeps.

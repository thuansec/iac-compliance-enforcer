# Terraform functions iace evaluates

iace evaluates Terraform statically (ADR 0003), so it only evaluates functions that are pure, are
bounded, and behave in iace the way they do in Terraform. Every other function call is
**unknown**: the scan goes on, and policies see an unknown value. It is never an error.

The table lives in `internal/terraform/functions.go` (`supportedFunctions` and
`unboundedFunctions`). `TestFunctionTableMatchesReference` fails when this page and the code
disagree, and `TestSupportedFunctions` has a case for every function.

## Supported functions

Each function in this table uses the go-cty stdlib implementation, because it behaves as
Terraform's function does. Terraform uses most of these stdlib functions directly. The `to*`
conversions are Terraform's own wrappers around the same cty conversions. A name in
Terraform's `core::` namespace (`core::upper`) is the same function.

| group | functions |
|---|---|
| string | `chomp`, `format`, `formatlist`, `join`, `lower`, `split`, `substr`, `title`, `trim`, `trimprefix`, `trimspace`, `trimsuffix`, `upper` |
| collection | `chunklist`, `coalescelist`, `compact`, `concat`, `contains`, `element`, `flatten`, `keys`, `merge`, `range`, `reverse`, `slice`, `sort`, `values`, `zipmap` |
| type conversion | `can`, `tobool`, `tolist`, `tomap`, `tonumber`, `tostring`, `try` |
| encoding | `jsondecode`, `jsonencode` |
| numeric | `abs`, `max`, `min`, `signum` |

## Not evaluated yet

These are unknown today. The backlog task that adds each is in brackets.

- Terraform's own implementations, which differ from go-cty's [T-0105b]: `length` (it accepts
  strings), `coalesce` (it skips empty strings), `index` (go-cty's looks up a key; Terraform's
  finds a value), `replace` (`/regex/` patterns), `regex`, `regexall`, `startswith`,
  `endswith`, `strcontains`, `base64encode`, `base64decode`, `cidrsubnet`, `cidrhost`,
  `cidrnetmask`, and `lookup` (go-cty's needs a non-null default; Terraform's default is
  optional and may be null).
- Functions that build sets or compare all pairs, which need a bounded implementation
  [T-0105b]: `distinct`, `toset`, `setunion`, `setintersection`, `setsubtract`. cty hashes a
  number by its first ten significant digits, so a set of close numbers compares every pair,
  and comparing two numbers costs as much as their decimal digits.
- Filesystem functions, confined to the module directory [T-0105c]: `file`, `fileexists`,
  `templatefile`.

## Always unknown

- Impure functions: `timestamp`, `plantimestamp`, `uuid`, `bcrypt` and the other random or
  time-dependent ones.
- Provider-defined functions (`provider::aws::arn_parse`), which run provider code.
- Functions whose cost iace does not bound yet (`indent`, `setproduct`, `ceil`, `floor`, `pow`,
  `parseint`, and so on).
- `type`, which only exists in the Terraform console.
- Any name Terraform does not define.

A call to an unsupported function is unknown, along with whatever is computed from it. The
module gets one `unsupported_function` warning per function name, at the first call. If an
argument is sensitive, the unknown result stays sensitive.

## Bounds

Scanned Terraform is untrusted, so every call to a supported function is bounded. Sizes are
measured as for local values: one unit per value, plus one per string byte, map key, attribute
name and decimal digit of a number's magnitude. cty formats, converts and compares numbers in
decimal, so `tostring(1e6000000)` costs as much as six million digits.

Argument sizes are checked before the arguments are converted to the function's parameter
types. Converting a number to a string, for example, costs as much as its digits.

| bound | value |
|---|---|
| arguments of one call, together | 2^18 units |
| result of one call | 2^18 units, nested at most as deep as the parse nesting limit |
| `format` and `formatlist` | checked before the call: the format string, every width and precision, and each verb printing the largest argument escaped six times, multiplied by the row count for `formatlist` |
| `range` | 1,024 elements (go-cty's own limit; past it the call fails, and the local is unknown) |
| work across a module | 2^23 units (about 1.5s of evaluation at worst): the size of every call's arguments and result |

A call over a bound is unknown, keeps the sensitivity of its arguments, and adds a
`function_limit` warning at the expression. The input document reports it as a
`limit_exceeded` coverage gap.

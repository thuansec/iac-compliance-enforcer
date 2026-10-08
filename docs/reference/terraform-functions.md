# Terraform functions iace evaluates

iace evaluates Terraform statically (ADR 0003), so it only evaluates functions that are pure, are
bounded, and behave in iace the way they do in Terraform. Every other function call is
**unknown**: the scan goes on, and policies see an unknown value. It is never an error.

The table lives in `internal/terraform/functions.go` (`supportedFunctions` and
`unboundedFunctions`). `TestFunctionTableMatchesReference` fails when this page and the code
disagree, and `TestSupportedFunctions` has a case for every function.

## Supported functions

Most functions in this table use the go-cty stdlib implementation, because it behaves as
Terraform's function does. Terraform uses most of these stdlib functions directly. The `to*`
conversions are Terraform's own wrappers around the same cty conversions. Functions marked *
have no matching stdlib function. iace implements them in
`internal/terraform/functions_terraform.go` from Terraform's documentation, never from its
source (BUSL-1.1). A name in Terraform's `core::` namespace (`core::upper`) is the same
function.

| group | functions |
|---|---|
| string | `chomp`, `endswith`\*, `format`, `formatlist`, `join`, `lower`, `regex`\*, `regexall`\*, `replace`\*, `split`, `startswith`\*, `strcontains`\*, `substr`, `title`, `trim`, `trimprefix`, `trimspace`, `trimsuffix`, `upper` |
| collection | `chunklist`, `coalesce`\*, `coalescelist`, `compact`, `concat`, `contains`, `element`, `flatten`, `index`\*, `keys`, `length`\*, `lookup`\*, `merge`, `range`, `reverse`, `slice`, `sort`, `values`, `zipmap` |
| type conversion | `can`, `tobool`, `tolist`, `tomap`, `tonumber`, `tostring`, `try` |
| encoding | `base64decode`\*, `base64encode`\*, `jsondecode`, `jsonencode` |
| numeric | `abs`, `max`, `min`, `signum` |
| filesystem | `file`\*, `fileexists`\*, `templatefile`\* |

## Not evaluated yet

These are unknown today. The backlog task that adds each is in brackets.

- Network functions [T-0105e]: `cidrsubnet`, `cidrhost`, `cidrnetmask`.
- Functions that build sets or compare all pairs, which need a bounded implementation
  [T-0105f]: `distinct`, `toset`, `setunion`, `setintersection`, `setsubtract`. cty hashes a
  number by its first ten significant digits, so a set of close numbers compares every pair,
  and comparing two numbers costs as much as their decimal digits.

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
| `contains`, `index` with sets | when the list's elements or the value can hold a set, the sizes of both arguments multiplied, charged to the module work (cty compares sets element by element, and colliding number hashes make that pairwise) |
| regular expression patterns | at most 4 KiB, charged 64 units per byte plus one per rune their classes expand to (`\pL` is over a thousand), and parsed once per module for up to 256 patterns (each further one for every call); refused before compiling when a parse-tree estimate (never below Go's program) passes 8,192 instructions, and when the compiled program passes 4,096 |
| regular expression matching | each search charged program size × (groups + 1) × (input length + 1) before it runs, since finding all matches searches again after each one and each search can scan to the end; `regexall` and `replace` with `/re/` stop at the matches the remaining work affords (and at what a result can hold), else the call is unknown. Long inputs with many matches are therefore unknown |
| `replace` output | exact for a plain substring; for `/re/`, the unmatched text plus, per match, the replacement with each `$` reference counted as the whole match, checked before the result is built |
| work across a module | 2^23 units (about 1.5s of evaluation at worst, except for conversions into set types, which are not bounded yet: T-0116): the size of every call's arguments and result |

A refused call still spends module work: as much as was measured of its arguments, so refused
calls cannot repeat for free. A call over a bound is unknown, keeps the sensitivity of its
arguments, and adds a `function_limit` warning at the expression. The input document reports it as a
`limit_exceeded` coverage gap.

## Semantics of iace's own functions

| function | behavior |
|---|---|
| `length(v)` | Grapheme clusters of a string; elements of a list, set or map; elements or attributes of a tuple or object, known from its type even when its value is unknown. Any other type is an error. |
| `coalesce(vals...)` | The first argument that is neither null nor `""`, converted to the arguments' common type. An unknown argument before it makes the result unknown. Mixed types that do not unify, or no such argument, are errors. |
| `index(list, value)` | The position of the first equal element of a list or tuple. An unknown list or value, or an unknown comparison before a match, makes the result unknown. An empty list or a missing value is an error. |
| `lookup(map, key, default?)` | A map's element or an object's attribute. A missing key returns the default (it may be null; for a map it is converted to the element type), and is an error without one. A map or key that is not wholly known makes the result unknown, as in Terraform. |
| `startswith`, `endswith`, `strcontains` | String prefix, suffix and substring tests. |
| `replace(str, substr, rep)` | A `substr` wrapped in slashes (`"/\\d+/"`) is an RE2 regular expression whose matches are replaced with Go's `$1`, `${name}` expansion. Any other `substr` is replaced literally, and `""` inserts `rep` between every character. An invalid expression is an error. |
| `base64encode(s)`, `base64decode(s)` | Standard Base64 of a string's UTF-8 bytes. Decoding fails on invalid Base64 or a result that is not UTF-8. |

A result computed from a sensitive argument stays sensitive. That includes `lookup`
falling back to its default, and `index` over a list holding a sensitive element. iace marks
more than Terraform does: `length`, `lookup`, `coalesce` and the string tests take on every
sensitive mark anywhere inside their arguments. So `lookup(obj, "b")` is sensitive when only
`obj.a` is. This errs on the side of hiding values.

## Filesystem functions

`file`, `fileexists` and `templatefile` read only inside the module's directory, through a
sub-root of the scan root (`os.Root`). Neither `..` nor a symlink can leave that directory, even
to a file elsewhere in the repository. Relative paths resolve against the module directory,
which is Terraform's working directory for a root module, and `path.module` is `"."`. Child
module instances will resolve against the root module (T-0107). `path.root` and `path.cwd` are
unknown.

| case | result |
|---|---|
| absolute, `~`, drive-letter or `..`-escaping path | unknown, `file_outside_module` warning |
| missing file (`file`, `templatefile`), directory, symlink leaving the module, file over 1 MiB, not UTF-8 | unknown, `file_unreadable` warning |
| `fileexists` on a missing path | `false` |
| template syntax error, a variable not in `vars`, `var.*` or `local.*` in the template, `templatefile` inside a template | unknown, `template_error` warning at the template file |
| `vars` not a map or object, or a key that is not an identifier | unknown, `evaluation` warning (as in Terraform, an argument error) |
| `vars` or the path not wholly known | unknown |

Each call charges 1 KiB of function work before it touches the filesystem. A read never reads
more than the work left (a larger file is a `function_limit`), and charges its size. The result
is bounded like any function result, so a file over 2^18 bytes is read but unknown.

Differences from Terraform, all on the side of unknown:
- A template whose whole text is one interpolation (`${list}`) returns that value in Terraform.
  iace converts the result to a string, so a number becomes a string, and a list or object is a
  `template_error`.
- A missing file is an error in Terraform, so `try(file("x"), "")` falls back to `""`. In
  iace it is unknown, and `try` cannot see past an unknown, so the result is unknown too.

Templates pass the same nesting and operator guard as expressions and use the same bounded
function table. Their own diagnostics, such as `unsupported_function`, point at the template
file.

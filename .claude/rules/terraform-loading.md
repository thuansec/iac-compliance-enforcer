---
paths:
  - "internal/terraform/**"
  - "internal/fsutil/**"
---

# Loading untrusted Terraform

Load the `iace-terraform-parsing` and `iace-security` skills before changing these packages.

- Never execute anything from the scanned repository: no terraform, providers, modules or hooks.
- Read scanned files only through `internal/fsutil` (`os.Root` confinement, size caps, no symlink escape).
- Anything that can't be resolved statically becomes **unknown** (with its path recorded), never an error.
- Every limit hit or unresolved module adds a `coverage_gaps` entry. Users must see what was not checked.
- Output is deterministic: sorted files, keys, instances and resources.

# Source patches

Only source scripts are represented as patches in this directory. The release
build also performs a deterministic, reversible PE-header transformation on
the pinned Cygwin executables listed by `build/import-upstream.sh`: it clears
`IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` and
`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`. `build/verify-official-binaries.sh`
reverses those two bits in a temporary copy and requires the resulting bytes to
match the pinned official SHA-256 exactly.

`blockcheck2-machine-report.patch` adds an opt-in tab-separated machine report
with explicit per-service/per-protocol outcomes and configurable k-of-n
validation. It does not change strategy generation or ordering.

`blockcheck2-custom-candidates.patch` adds a small set of field-observed
strategies to the bounded first-run list. The fallback remains available when
the short list does not cover the current network.

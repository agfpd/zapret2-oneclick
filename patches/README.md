# Source patches

Only source scripts may be patched. Official zapret2/WinDivert/Cygwin binaries
remain byte-identical to the pinned upstream artifacts.

`blockcheck2-machine-report.patch` adds an opt-in tab-separated machine report
without changing strategy generation, ordering, or test verdicts.

`blockcheck2-custom-candidates.patch` adds a small set of field-observed
strategies to the bounded first-run list. The fallback remains available when
the short list does not cover the current network.

# Source patches

Only source scripts may be patched. Official zapret2/WinDivert/Cygwin binaries
remain byte-identical to the pinned upstream artifacts.

`blockcheck2-machine-report.patch` adds an opt-in tab-separated machine report
without changing strategy generation, ordering, or test verdicts.

`blockcheck2-custom-candidates.patch` adds a small set of field-observed
strategies to the bounded first-run list. The fallback remains available when
the short list does not cover the current network.

`blockcheck2-native-winws-launch.patch` keeps the official winws2 binary
byte-identical but starts blockcheck instances through a native Windows parent.
The helper disables only high-entropy ASLR for each short-lived diagnostic
child, avoiding Cygwin's fixed cygheap range while retaining standard ASLR;
the production service keeps the upstream mitigation unchanged. NUL-delimited
argument transfer is tested end-to-end against the bundled Cygwin parser, and
blockcheck still owns and terminates each exact PID.

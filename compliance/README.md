# Cygwin corresponding-source gate

The runtime binaries may be used during development, but a distributable
release must have a sibling `zapret2-oneclick-<version>-sources.zip` containing:

1. the exact Cygwin package manifest used to assemble `vendor/cygwin`;
2. the corresponding source archives and their upstream checksums;
3. license texts and build scripts/patches needed to recreate changed files;
4. the unmodified zapret2 v1.0.2 source tree and this project's source patches.

`Build-SourceArtifact.ps1` fails closed if any binary package lacks a locked
source archive or if an archive hash differs. `Build-CygwinRuntime.ps1`
assembles the runtime from a verified Cygwin setup snapshot, materializes
non-portable Cygwin symlinks, and overlays only the pinned HTTP/3 curl files
needed by blockcheck2. The checked-in lock covers 101 installed Cygwin packages
plus the legacy service DLL and HTTP/3 curl dependency sources.

Normal rebuilds compare resolved package paths and hashes with the checked-in
lock and fail on drift. Updating Cygwin is an explicit maintenance action using
`-UpdateLock`, followed by Windows simulation and a regenerated source
artifact; a moving mirror can never silently change release inputs.

The corresponding-source builder was exercised on Windows against the locked
cache and produced a 441 MB archive with 95 unique entries. Release packaging
must regenerate this sibling artifact; it remains intentionally ignored by
Git because it is a release output, not source control input.

# zapret2-oneclick

Private Windows 10/11 x86_64 one-click wrapper around official zapret2 v1.0.2.

Current target core is YouTube + Discord, including the curated Discord
media/STUN UDP profile. Hostlists were derived from Microsoft Edge netlogs on
the Windows acceptance host; they remain versioned data, not launcher code.

## Install and operate

1. Extract the release to a local directory on Windows 10/11 x86_64.
2. Double-click `setup.cmd` and approve the UAC prompt.
3. Leave other DPI-bypass tools and VPN clients stopped while blockcheck2
   discovers and validates strategies. Discovery tests each requested protocol;
   every selected candidate must then pass five validation attempts. A force
   scan runs only for a service/protocol/IP family without a common candidate.
4. The launcher verifies every vendored file, installs into
   `%ProgramData%\zapret2-oneclick`, validates the generated winws2 config with
   `--dry-run`, and creates the auto-start `zapret2-oneclick` Windows service.

Useful maintenance commands, run from the extracted release directory:

```bat
setup.cmd -Rescan
setup.cmd -Rollback
uninstall.cmd
uninstall.cmd -KeepLogs
```

Validated strategy state is retained across an upgrade unless `-Rescan` is
given. Install transcripts live under
`%ProgramData%\zapret2-oneclick.logs\runtime\logs`. Uninstall removes the
service, payload, and WinDivert driver when no other known WinDivert consumer
is running; otherwise it deliberately leaves the shared driver in place.

## Architecture

- `setup.cmd` is the no-prerequisite entry point and delegates to elevated
  Windows PowerShell 5.1.
- The PowerShell orchestrator provides transactional payload replacement,
  hash verification, selection metadata, rollback, SCM lifecycle, and
  uninstall.
- A reproducibly assembled portable Cygwin 3.6.9 runtime executes the original
  upstream `blockcheck2.sh`. A narrow patch adds a TSV machine report without
  changing strategy generation.
- The blockcheck copy of winws2 has no adjacent `cygwin1.dll`, so it runs inside
  Cygwin. The service copy has the official DLL adjacent and runs standalone
  under Windows Service Control Manager.
- Generated production arguments are stored in `runtime\active.conf`; paths are
  absolute, and winws2 parses the file through its upstream `@config` support.

## Safety boundaries

- Run only on Windows 10/11 x86_64.
- Administrator rights are required for WinDivert and Windows service setup.
- WinDivert can trigger antivirus products and can conflict with kernel-mode
  firewall/AV software.
- ARM64 is not supported; the available driver path requires Test Signing.
- Distribute the generated corresponding-source zip alongside every binary
  release; `build/check-release-readiness.ps1` fails closed on an incomplete
  package/source lock or vendor hash mismatch.

## Extending the service catalog

The launcher is catalog-driven. Adding a normal HTTP(S)/QUIC service does not
require rebuilding the binaries:

1. add `config/hostlists/<service>.txt` (one parent domain per line; subdomains
   match automatically in winws2);
2. append a group to `config/services.json` with a stable `id`, the hostlist
   path, representative `probeDomains`, and any of `https-tls12`,
   `https-tls13`, `quic`;
3. run `setup.cmd -Rescan`; the selector discovers, validates five times, and
   falls back to a force scan only for groups without a stable candidate;
4. confirm the full browser flow in a Windows network trace before committing
   the list. Avoid broad parents such as all of `googleusercontent.com` unless
   the trace proves they are required.

Non-web protocols need a separately reviewed raw WinDivert filter and curated
Lua profile. Discord's `discord-media-stun` profile is the first such example;
blockcheck2 cannot validate it, so acceptance includes a real voice/media call.

## Rebuilding vendored inputs

`build/import-upstream.sh` downloads official zapret2 v1.0.2, verifies the
official archive and binary manifests, pins the official Windows bundle commit,
and reapplies the machine-report patch. `Build-CygwinRuntime.ps1` must be run on
Windows to assemble the portable runtime and source lock. Before packaging:

```powershell
.\build\check-release-readiness.ps1
.\build\Build-SourceArtifact.ps1
```

Ship the generated source zip beside the binary release. Upstream versions and
hashes are pinned in `checksums/upstream.lock.json`; binary releases must never
be substituted from mirrors or third-party forks.

# Third-party notices

This private bundle contains unmodified binaries and source files from
[`bol-van/zapret2`](https://github.com/bol-van/zapret2), pinned to v1.0.2.
The upstream license is included under `vendor/zapret2/docs/LICENSE.txt`.

The portable POSIX runtime is derived from the official
[`bol-van/zapret-win-bundle`](https://github.com/bol-van/zapret-win-bundle),
pinned by commit in `checksums/upstream.lock.json`. Cygwin's runtime library is
LGPL-3.0-or-later with the Cygwin linking exception; many bundled utilities are
GPL or use other free-software licenses.

The runtime core is reproducibly assembled from Cygwin 3.6.9 packages and uses
the pinned win-bundle only for the seven files that provide an HTTP/3-capable
curl. Release production is gated on generating a corresponding-source
artifact for every distributed Cygwin package and those custom dependencies.
See `compliance/README.md`. Do not distribute a release zip without its
matching source artifact.

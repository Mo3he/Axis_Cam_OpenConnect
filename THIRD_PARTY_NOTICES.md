# Third-party notices

The packaging and app code in this repository is licensed under the BSD 3-Clause
License (see `LICENSE`). The package bundles the following third-party
components, each under its own license.

## OpenConnect (libopenconnect, statically linked into `lib/gp-client`)

- Project: <https://www.infradead.org/openconnect/>
- Copyright (C) David Woodhouse and the OpenConnect contributors.
- License: **LGPL-2.1-or-later** (full text shipped as `lib/COPYING.LGPL`).
- Version: see `OPENCONNECT_VERSION` in the `Dockerfile`.
- Built unmodified from the release tarball
  `https://www.infradead.org/openconnect/download/openconnect-<version>.tar.gz`
  (SHA-256 pinned in the `Dockerfile`) and linked statically into `gp-client`,
  whose source (`app/client/gp_client.c`) is part of this repository. As
  LGPL-2.1 section 6 requires, everything needed to relink `gp-client` against
  a modified libopenconnect is available: the complete source of this
  repository and the `Dockerfile` that builds it. On request, the maintainer
  provides the corresponding source for any released package; see
  `SECURITY.md` for contact details.

## OpenSSL (statically linked into `lib/gp-client`)

- Project: <https://www.openssl.org/>
- License: **Apache-2.0**.
- Version: see `OPENSSL_VERSION` in the `Dockerfile`.

## libxml2 (statically linked into `lib/gp-client`)

- Project: <https://gitlab.gnome.org/GNOME/libxml2>
- Copyright (C) Daniel Veillard and the libxml2 contributors.
- License: **MIT**.
- Version: see `LIBXML2_VERSION` in the `Dockerfile`.

## zlib (statically linked into `lib/gp-client`)

- Project: <https://zlib.net/>
- Copyright (C) Jean-loup Gailly and Mark Adler.
- License: **Zlib**.
- Version: see `ZLIB_VERSION` in the `Dockerfile`.

## Go netstack sidecar (`lib/netstack_proxy`)

Statically linked Go binary built from:

- **gVisor** (`gvisor.dev/gvisor`): Copyright The gVisor Authors, **Apache-2.0**.
- **wireguard-go** (`golang.zx2c4.com/wireguard`, `tun/netstack`): Copyright (C)
  Jason A. Donenfeld, **MIT**.
- **golang.org/x/{crypto,net,sys,time}**: Copyright The Go Authors,
  **BSD-3-Clause**.
- **github.com/google/btree**: Copyright Google, **Apache-2.0**.

## CA certificates (`lib/ca-bundle.crt`)

- The Mozilla CA certificate list as packaged by Ubuntu's `ca-certificates`,
  used only when the camera has no CA bundle of its own.
- License: **MPL-2.0**.

## Axis ACAP Native SDK

- Project: <https://developer.axis.com/acap/>
- Used at build time to compile and package the application.

## Trademarks

GlobalProtect is a trademark of Palo Alto Networks, Inc. WireGuard is a
registered trademark of Jason A. Donenfeld. All other product names, logos and
brands are property of their respective owners. This is an independent community
project and is not affiliated with or endorsed by Palo Alto Networks, the
OpenConnect project, or Axis Communications.

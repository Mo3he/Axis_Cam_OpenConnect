# OpenConnect ACAP for Axis Cameras

[![Release](https://img.shields.io/github/v/release/Mo3he/Axis_Cam_OpenConnect?style=flat)](https://github.com/Mo3he/Axis_Cam_OpenConnect/releases)
[![License](https://img.shields.io/github/license/Mo3he/Axis_Cam_OpenConnect?style=flat)](LICENSE)
[![Build](https://github.com/Mo3he/Axis_Cam_OpenConnect/actions/workflows/build.yml/badge.svg)](https://github.com/Mo3he/Axis_Cam_OpenConnect/actions/workflows/build.yml)
[![Super-Linter](https://github.com/Mo3he/Axis_Cam_OpenConnect/actions/workflows/super-linter.yml/badge.svg)](https://github.com/Mo3he/Axis_Cam_OpenConnect/actions/workflows/super-linter.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor%20My%20Work-EA4AAA?style=flat&logo=github&logoColor=white)](https://github.com/sponsors/Mo3he)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/mo3he)

An **[OpenConnect](https://www.infradead.org/openconnect/)-based VPN client that
runs directly on Axis cameras** as an ACAP application. It currently speaks the
GlobalProtect protocol (Palo Alto Networks GlobalProtect and Prisma Access). It
runs entirely in **userspace** with **no root** and no kernel TUN device, makes
the camera reachable from your VPN, and lets the camera route its own traffic
out through the tunnel.

> **Disclaimer:** Independent, community-developed ACAP package. Not an official
> Axis product and not affiliated with, endorsed by, or supported by Axis
> Communications AB, the OpenConnect project or Palo Alto Networks. Use at your
> own risk.

> **Notice:** GlobalProtect and Prisma Access are trademarks of Palo Alto
> Networks, Inc. This app does not contain GlobalProtect software; it uses
> OpenConnect's independent implementation of the GlobalProtect protocol.

## Overview

- **No root required:** runs as the standard unprivileged `sdk` ACAP user.
- **No kernel TUN / CAP_NET_ADMIN:** the client hands the tunnel's packets to a
  userspace gVisor netstack, the same data plane as the WireGuard and OpenVPN
  ACAPs.
- **Portal or gateway:** connects through a GlobalProtect portal (with optional
  gateway selection) or straight to a gateway, over ESP (UDP) with SSL (TCP)
  fallback.
- **Sign in from the settings page:** whatever the portal asks for (password,
  one-time code, RADIUS challenge, or SAML single sign-on with any MFA the
  identity provider uses) is shown on the camera's settings page and answered
  there. Client certificates are supported too.
- **Stays connected unattended:** after a sign-in the camera keeps the gateway
  session and reuses it for reconnects and restarts until the gateway ends it,
  just like the GlobalProtect client on a laptop. Only then is a new sign-in
  needed (or none, if a stored password is all the portal asks for).
- **Honest host information:** the HIP report describes the camera as it is:
  model, serial number, AXIS OS version, hostname and network interfaces.
- **Lockout-safe retries:** a stored password rejected by the portal pauses
  retries for 15 minutes; a sign-in that needs a person, or an untrusted server
  certificate, waits instead of retrying. Network failures retry with a backoff
  from 15 seconds up to 10 minutes.

## Compatibility

| Package | AXIS OS | Architecture | Status |
|---|---|---|---|
| ACAP 4 | 11.11 - 13 | aarch64 | Beta |
| ACAP 4 | 11.11 - 13 | armv7hf | Beta |

The client (built on libopenconnect) and its TLS, XML and compression libraries
are statically linked, so the package only depends on the camera's C library. Gateways must assign an IPv4
address; IPv6-only tunnels are not supported.

Tested against a Prisma Access (GlobalProtect) deployment with Entra ID SAML
single sign-on (portal and gateway sign-in, HIP report, ESP transport) and
against OpenConnect's own GlobalProtect test server. Other OpenConnect protocols
(AnyConnect, Pulse, Fortinet, F5, Array) are not enabled yet.

## Installation

Download the `.eap` for your camera's architecture from the
[Releases page](https://github.com/Mo3he/Axis_Cam_OpenConnect/releases) and
install it in the camera web interface under **Apps -> Add app**, then open the
app's settings page.

| Architecture | File |
|---|---|
| aarch64 | `OpenConnect_VPN_<version>_aarch64.eap` |
| armv7hf | `OpenConnect_VPN_<version>_armv7hf.eap` |

## Configuration

Open **Apps -> OpenConnect VPN -> Open** and:

1. Enter the **portal** address (or choose **Gateway directly** and enter a
   gateway address) and the **username** of the camera's VPN account.
2. Tick **Enable VPN connection** and click **Save & Connect**.
3. If the portal needs anything beyond a stored password (a one-time code,
   single sign-on), the status shows **Sign-in required**: click **Sign in** and
   follow the steps in the Sign-in card.

The status card shows the VPN IP and transport once connected; the service log
below it shows the client's output.

### Signing in

The camera relays the portal's login forms to the settings page as they come:

- **Password and one-time codes:** the Sign-in card shows each form the portal
  sends (password, OTP code, RADIUS challenge, gateway choice) with the
  portal's own prompt text. Type the answer and click **Continue**. A password
  typed here is used for that sign-in only and is not stored.
- **Single sign-on (SAML):** click **Open the sign-in page**. The identity
  provider's login opens in a new browser tab, where push notifications, number
  matching, security keys and other MFA work as usual. When the portal reports
  that the sign-in is complete, click the **Send to camera** bookmark on that
  tab, and the camera finishes the connection. Create the bookmark once by
  dragging the button from the Sign-in card to the bookmarks bar. Without the
  bookmark, copy the final page's `globalprotectcallback:` link, or its page
  source, and paste it into the Sign-in card.

The final step needs the bookmark or a paste because browsers do not let one
website (the camera) read pages from another (the portal), which is where the
portal hands over the result. Embedding the sign-in in a frame does not help:
identity providers refuse to be framed for exactly this reason.

Some deployments ask for single sign-on twice: once for the portal and, unless
the portal issues an authentication override cookie, once more for the gateway.
The Sign-in card then shows **Step 2 of 2**; the browser is usually still
signed in to the identity provider, so the second sign-in is quick. Enabling
authentication override cookies on the portal and gateways avoids the second
step.

If the portal or gateway refuses a sign-in result you sent, the camera stops
and waits for you rather than submitting anything again, so a failed hand-off
cannot add a series of failed sign-ins to the account.

After a successful sign-in the camera saves the gateway session (readable only
by the app) and uses it for every reconnect and app restart, so a camera
without a person nearby stays connected for as long as the gateway allows. The
session ends when the gateway's login lifetime expires, when the gateway logs
it out, when the server or username changes, or when the VPN is disabled. The
camera then signs in again by itself if a stored password is all the portal
needs; otherwise the status returns to **Sign-in required**. Ask the portal
administrator how long the login lifetime for the camera accounts is.

### Keep-alive

A gateway also ends a session that carries no traffic for its idle timeout
(often a few hours). A camera that nobody views for that long would then need a
new sign-in. **Keep-alive** under **Advanced** (`KeepAliveMinutes`, off by
default) sends a small DNS query for the portal's name to the DNS server the
gateway pushed, through the tunnel, every that many minutes. Pick an interval
below the idle timeout, for example 30.

The idle timeout is your VPN administrator's policy, and the keep-alive
deliberately defeats it, so only turn it on with their agreement. It does not
extend the login lifetime: once that expires the gateway ends the session
anyway. It needs the gateway to push a DNS server; otherwise the log says so
and it stays off.

A stored **Password** is optional. Store it only for portals that ask for
nothing else; with a one-time code or single sign-on, leave it empty.

### Host information (HIP)

When a gateway asks for a host information profile, the camera answers with its
real details:

| HIP field | Value |
|---|---|
| OS | `AXIS OS <version> (<product name>)`, e.g. `AXIS OS 12.11.77 (AXIS P3288-LV Dome Camera)` |
| OS vendor | `Axis Communications` |
| Host name | The camera's hostname |
| Host ID and serial number | The camera's serial number |
| Network interfaces | Every active interface with its MAC and IP addresses |
| Client version | The version the portal reports |
| Anti-malware, disk backup, disk encryption, firewall, patch management, DLP | Empty: the camera runs none of these |

Gateways that enforce HIP profiles written for laptops will not match a camera.
Create a HIP object for the cameras instead (for example host info, OS contains
`AXIS OS`, or the serial numbers) and use it in the policy for the camera
accounts. The client reports itself to the portal as Linux by default, since
AXIS OS is Linux-based; change **Client OS reported to the portal** under
Advanced only if the portal does not admit Linux clients.

### Server certificate

Public portal certificates work out of the box. For a privately issued
certificate either upload the issuing CA under **Advanced**, or, after a failed
connection, review the fingerprint shown on the status card and click **Trust
this certificate** to pin it (`ServerCert`).

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `Enabled` | `no` | Connects when set to `yes`. |
| `Server` | empty | Portal or gateway address. |
| `ServerType` | `portal` | `portal`, or `gateway` to skip the portal. |
| `Gateway` | empty | Preferred gateway from the portal's list. |
| `Username` | empty | Account name. |
| `Password` | empty | Optional stored password for unattended sign-in. Write-only. |
| `ServerCert` | empty | Trusted server certificate pin, for example `pin-sha256:...`. |
| `ReportedOs` | `linux` | Client OS reported to the portal: `linux`, `linux-64`, `win`, `mac-intel`. |
| `HttpProxyPort` | `28080` | Outbound HTTP proxy port on `127.0.0.1`. |
| `Socks5Port` | `21080` | Outbound SOCKS5 port on `127.0.0.1`. |
| `ForwardPorts` | `80,443,554` | Camera ports forwarded from the VPN IP (up to 16). |
| `KeepAliveMinutes` | `0` | Keep-alive interval in minutes (1 to 1440), `0` for off. See [Keep-alive](#keep-alive). |

The client certificate (PEM certificate and key in one file) and the extra CA
are uploaded on the settings page and stored in the app's `localdata`, readable
only by the app.

The settings page reads and writes through the app's own endpoint at
`/local/OpenConnect_VPN/api/settings`, reachable only through the camera's
authenticated reverse proxy. `param.cgi` is used only as a fallback.

## Ports & security

- **Camera from the VPN:** the ports in `ForwardPorts` on the VPN IP forward to
  the same ports on the camera, and an inbound **SOCKS5** proxy on
  `<vpn-ip>:1080` reaches any local camera port. Both are only reachable through
  the tunnel; the camera's own authentication still applies. The gateway's
  security policy decides what reaches the VPN IP: if some ports answer from
  the VPN (for example HTTP) while others connect and then reset (HTTPS, RTSP),
  ask the VPN administrator to allow that traffic to the camera accounts.
- **Camera to the VPN:** an HTTP proxy (`127.0.0.1:28080`) and a SOCKS5 proxy
  (`127.0.0.1:21080`) on the camera's loopback interface route traffic through
  the tunnel. Point the camera's global proxy setting at one of them. Names
  resolve with the DNS servers pushed by the gateway first. The default ports
  differ from those of the Tailscale, WireGuard and OpenVPN apps (8080/1080) and
  the NetBird app (18080/11080), so they can run side by side; if a port is
  still taken, the status card says so.
- **Settings API:** `127.0.0.1:2210`, reachable only through the reverse proxy
  and restricted to `admin`. Secrets are never returned by it.
- **Sign-in:** answers typed on the settings page travel through the camera's
  authenticated reverse proxy (`admin` only) to the client's standard input.
  Passwords typed there are kept in memory for that sign-in only.
- **Secrets at rest:** the optional stored password lives in the camera's
  parameter store; the gateway session cookie is kept in a `0600` file in the
  app's `localdata` and discarded when the VPN is disabled or the account
  changes. Disabling the VPN also logs the session out at the gateway. No
  secret appears on a command line.
- Nothing listens on the camera's external interfaces.

## How it works

```text
lib/gp-client (libopenconnect, GlobalProtect protocol)
   │  TLS/ESP to the gateway                │ SOCK_DGRAM socketpair ($VPNFD)
   │                                        ▼
   │                          netstack_proxy (gVisor userspace TCP/IP)
   │                            ├─ <vpn-ip>:80/443/554 -> [::1] (camera; 127.0.0.1 as fallback)
   │                            ├─ <vpn-ip>:1080 SOCKS5 -> [::1]:<any> (127.0.0.1 as fallback)
   │                            └─ 127.0.0.1:28080 / :21080 -> through the tunnel
OpenConnect_VPN (bridge): settings, sign-in relay, session, supervision
```

`gp-client` is a small client built on libopenconnect. It reports each login
form, SSO step, connection and reconnection as an event to the bridge, which
shows forms on the settings page and passes the answers back. Once the gateway
has assigned an address, the client runs `tun-script.sh`, which execs the
netstack sidecar with the socketpair fd and the pushed address, MTU and DNS
servers. The same `gp-client` binary generates the HIP report.

## Build from source

Docker or Podman is required; the Axis ACAP Native SDK image does the build.

```sh
./build.sh                 # aarch64 and armv7hf into ./releases
ARCHES=aarch64 ./build.sh  # a single architecture
```

The Dockerfile downloads and verifies (SHA-256) the OpenConnect, OpenSSL,
libxml2 and zlib release tarballs, cross-compiles them as static libraries,
links `app/client/gp_client.c` against them, and
fails if the result needs glibc symbols newer than 2.37 (the `__isoc23_*`
family that AXIS OS below 12.10 lacks) or links any of them dynamically.

### Development loop

The ACAP SDK image is x86-64, so on an Apple Silicon Mac every build runs
under emulation and a full build takes about 25 minutes. `dev.sh` builds on a
native x86-64 Docker host instead, where the layer cache keeps the libraries:
the first build takes about three minutes, later ones a few seconds plus the
changed client or bridge. It then installs the package on a test camera.

```sh
export BUILD_HOST=user@build-host CAMERA=camera-ip
./dev.sh all       # sync, build on BUILD_HOST, install on CAMERA
./dev.sh log       # the app's recent log on the camera
```

Passwords are prompted for, or taken from `CAMERA_PASS` and `SSHPASS`; nothing
is stored in the repository.

### CI

Every push builds both architectures and uploads the packages as workflow
artifacts. A nightly job checks for new OpenConnect releases, bumps the pin and
cuts a draft release holding the unsigned packages.

## Links

- Releases: <https://github.com/Mo3he/Axis_Cam_OpenConnect/releases>
- Issues: <https://github.com/Mo3he/Axis_Cam_OpenConnect/issues>
- OpenConnect: <https://www.infradead.org/openconnect/>
- OpenConnect GlobalProtect notes: <https://www.infradead.org/openconnect/globalprotect.html>
- ACAP documentation: <https://developer.axis.com/acap/>
- Axis Communications: <https://www.axis.com/>

## License

The packaging and app code in this repository is licensed under BSD 3-Clause
(see [LICENSE](LICENSE)). Bundled upstream components (OpenConnect under
LGPL-2.1, OpenSSL, libxml2, zlib, gVisor and others) are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

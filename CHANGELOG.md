# Changelog

All notable changes to this project are documented here. Each version
links to its full release notes on GitHub.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

- Fix HTTPS over the tunnel on AXIS OS 13. Its web server answers `127.0.0.1`
  in plain HTTP on every port, 443 included, so HTTPS to the camera through
  the tunnel failed. Forwarded ports and the inbound SOCKS5 proxy now connect
  to `[::1]`, which every AXIS OS version serves like the network (with TLS on
  443), and fall back to `127.0.0.1` for services that listen only there (such
  as port 80 on an HTTPS-only device).

## 0.1.0

- Initial release of OpenConnect VPN: a GlobalProtect-compatible client built
  on libopenconnect 9.21, running in userspace as the `sdk` user with the shared
  gVisor netstack data plane. Tested against Prisma Access with Entra ID SAML.
- Sign in from the settings page: password, one-time code and challenge forms
  are relayed live from the portal, and SAML single sign-on runs in the
  browser (any MFA) with a "Send to camera" bookmark or paste to finish,
  including a second gateway sign-in when the portal issues no override cookie.
  A rejected sign-in result is never resubmitted.
- The gateway session is kept and reused for reconnects and restarts until the
  gateway ends it; a stored password is optional, for portals that need nothing
  else. Disabling the VPN logs out and discards the session.
- The HIP report describes the camera itself: model, serial number, AXIS OS
  version, hostname and network interfaces, with no invented security products.
- Portal or direct gateway connections, client certificates, certificate
  pinning and CA upload.
- Lockout-safe retry policy and a status card with a "reconnecting" state
  while the gateway connection recovers.
- Outbound proxies default to 28080/21080 so they do not collide with the other
  VPN apps on the same camera; a port that is still taken is shown as a warning.
- Optional keep-alive (off by default) that sends a DNS query through the
  tunnel at a set interval, for gateways whose idle timeout would otherwise end
  the session of an unwatched camera.

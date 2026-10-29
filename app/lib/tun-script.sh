#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# OpenConnect --script-tun entry point. OpenConnect runs this once the tunnel is
# configured, with one end of a SOCK_DGRAM socketpair in $VPNFD and the pushed
# settings in INTERNAL_IP4_*. The netstack sidecar takes over this process (and
# its pid), so OpenConnect's SIGHUP to our process group on shutdown reaches it.
# Proxy ports come from the GP_* variables set by the app bridge.

LIB_DIR=$(dirname "$0")

if [ -z "$VPNFD" ]; then
	echo "tun-script: VPNFD not set; must be started by openconnect --script-tun" >&2
	exit 1
fi
if [ -z "$INTERNAL_IP4_ADDRESS" ]; then
	echo "tun-script: the gateway assigned no IPv4 address; IPv6-only tunnels are not supported" >&2
	exit 1
fi

if [ -n "$GP_SIDECAR_PIDFILE" ]; then
	echo $$ >"$GP_SIDECAR_PIDFILE"
fi

echo "tun-script: starting netstack for ${INTERNAL_IP4_ADDRESS} (mtu ${INTERNAL_IP4_MTU:-1400}, dns ${INTERNAL_IP4_DNS:-none})"

exec "$LIB_DIR/netstack_proxy" "$VPNFD" "${INTERNAL_IP4_ADDRESS}/32" \
	"${INTERNAL_IP4_MTU:-1400}" "${GP_HTTP_PORT:-28080}" "${GP_SOCKS_PORT:-21080}" \
	"${GP_FORWARD_PORTS:-80,443,554}" "${INTERNAL_IP4_DNS:-}"

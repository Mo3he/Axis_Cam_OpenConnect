#!/usr/bin/env bash
#
# Fast development loop: build on a remote x86-64 Docker host and install the
# result on a test camera.
#
# The ACAP Native SDK image is x86-64, so on an Apple Silicon Mac every build
# runs under emulation. Building on a native x86-64 host is much faster, and
# its Docker layer cache keeps OpenSSL, libxml2 and libopenconnect, so a change
# to the app only recompiles the client, the bridge and the package.
#
#   ./dev.sh build     sync the working tree to the build host and build there
#   ./dev.sh deploy    upload the package to the camera and start it
#   ./dev.sh all       build, then deploy
#   ./dev.sh log       show the app's recent log on the camera
#
# Environment:
#   BUILD_HOST   ssh destination of the x86-64 Docker host (required for build)
#   BUILD_DIR    directory on the build host (default: gp-dev)
#   ARCHES       architectures to build (default: aarch64)
#   CAMERA       camera address (required for deploy/log)
#   CAMERA_USER  camera user (default: admin)
#   CAMERA_PASS  camera password (prompted for when unset)
#   SSHPASS      ssh password, used through sshpass when set (otherwise ssh
#                keys or the ssh password prompt)

set -euo pipefail

REPO_ROOT=$(cd -P "$(dirname "$0")" && pwd)
APP=OpenConnect_VPN
BUILD_DIR=${BUILD_DIR:-gp-dev}
ARCHES=${ARCHES:-aarch64}
CAMERA_USER=${CAMERA_USER:-admin}
SSH_OPTS=(-o ControlMaster=auto -o "ControlPath=/tmp/dev-ssh-%r@%h-%p" -o ControlPersist=30m)

die() {
	echo "dev.sh: $*" >&2
	exit 1
}

remote() {
	if [ -n "${SSHPASS:-}" ]; then
		sshpass -e ssh "${SSH_OPTS[@]}" "$BUILD_HOST" "$@"
	else
		ssh "${SSH_OPTS[@]}" "$BUILD_HOST" "$@"
	fi
}

sync_to_host() {
	# Tracked and untracked-but-not-ignored files: uncommitted work included,
	# build output and local state left out. The remote copy is replaced, but
	# its releases/ survives so packages do not vanish between builds.
	(cd "$REPO_ROOT" && git ls-files -co --exclude-standard -z | tar --null -T - -czf -) |
		remote "mkdir -p '$BUILD_DIR' && cd '$BUILD_DIR' && find . -mindepth 1 -maxdepth 1 ! -name releases -exec rm -rf {} + && tar xzf -"
}

fetch_packages() {
	mkdir -p "$REPO_ROOT/releases"
	remote "cd '$BUILD_DIR/releases' && tar cf - *.eap" | tar xf - -C "$REPO_ROOT/releases"
}

cmd_build() {
	[ -n "${BUILD_HOST:-}" ] || die "set BUILD_HOST (e.g. user@build-host)"
	local start=$SECONDS
	echo "==> Syncing to $BUILD_HOST:$BUILD_DIR"
	sync_to_host
	echo "==> Building $ARCHES on $BUILD_HOST"
	remote "cd '$BUILD_DIR' && chmod +x build.sh ci/*.sh && ARCHES='$ARCHES' RUNTIME=docker ./build.sh" |
		grep -E "^==>|newest glibc|Creating Package|error:|Error" || true
	fetch_packages
	ls -l "$REPO_ROOT"/releases/*.eap
	echo "==> Built in $((SECONDS - start)) s"
}

camera() {
	curl -s --fail-with-body --digest -u "$CAMERA_USER:$CAMERA_PASS" -m "${CURL_TIMEOUT:-60}" "$@"
}

need_camera() {
	[ -n "${CAMERA:-}" ] || die "set CAMERA (the camera's address)"
	if [ -z "${CAMERA_PASS:-}" ]; then
		read -rsp "Password for $CAMERA_USER@$CAMERA: " CAMERA_PASS
		echo
	fi
}

cmd_deploy() {
	need_camera
	local eap
	eap=$(ls -t "$REPO_ROOT"/releases/${APP}_*_aarch64.eap 2>/dev/null | head -1)
	[ -n "$eap" ] || die "no aarch64 package in releases/; run ./dev.sh build first"
	echo "==> Installing $(basename "$eap") on $CAMERA"
	CURL_TIMEOUT=300 camera -F "packfil=@$eap" "http://$CAMERA/axis-cgi/applications/upload.cgi"
	echo
	camera "http://$CAMERA/axis-cgi/applications/control.cgi?action=start&package=$APP" >/dev/null || true
	sleep 3
	camera "http://$CAMERA/axis-cgi/applications/list.cgi" | grep -o "<application Name=\"$APP\"[^>]*" |
		grep -o 'Version="[^"]*"\|Status="[^"]*"' | tr '\n' ' '
	echo
	camera "http://$CAMERA/local/$APP/api/status" || true
	echo
}

cmd_log() {
	need_camera
	camera "http://$CAMERA/axis-cgi/admin/systemlog.cgi?appname=$APP" | grep -E '^[0-9]{4}-' | tail -"${LINES_SHOWN:-40}"
}

case "${1:-}" in
build) cmd_build ;;
deploy) cmd_deploy ;;
all)
	cmd_build
	cmd_deploy
	;;
log) cmd_log ;;
*)
	sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac

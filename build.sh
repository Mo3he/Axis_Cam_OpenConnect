#!/usr/bin/env sh
#
# Build the ACAP package for every architecture into ./releases.
#
#   ./build.sh                 # aarch64 and armv7hf
#   ARCHES=aarch64 ./build.sh  # one architecture
#   RUNTIME=podman ./build.sh  # force a container runtime

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME=${RUNTIME:-}
ARCHES=${ARCHES:-"aarch64 armv7hf"}

if [ -z "$RUNTIME" ]; then
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
		RUNTIME=docker
	elif command -v podman >/dev/null 2>&1; then
		RUNTIME=podman
	elif command -v docker >/dev/null 2>&1; then
		RUNTIME=docker
	else
		echo "Error: neither Docker nor Podman is available" >&2
		exit 1
	fi
fi

# Remove previous unsigned output only; signed packages must survive a rebuild.
mkdir -p "$REPO_ROOT/releases"
find "$REPO_ROOT/releases" -maxdepth 1 -type f -name '*.eap' ! -name 'signed_*' -delete

for arch in $ARCHES; do
	tag=$(echo "OpenConnect_VPN-${arch}" | tr '[:upper:]' '[:lower:]')
	output_dir="$REPO_ROOT/.build/${arch}"
	echo "==> Building ${arch} with ${RUNTIME}"
	rm -rf "$output_dir"
	mkdir -p "$output_dir"
	"$RUNTIME" build --build-arg ARCH="$arch" --target package -t "$tag" "$REPO_ROOT"
	container=$($RUNTIME create "$tag")
	"$RUNTIME" cp "$container:/opt/app/." "$output_dir/"
	"$RUNTIME" rm "$container" >/dev/null
	find "$output_dir" -type f -name "*.eap" -exec mv {} "$REPO_ROOT/releases/" \;
done

rm -rf "$REPO_ROOT/.build"

ls -lh "$REPO_ROOT"/releases/*.eap

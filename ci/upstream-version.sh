#!/usr/bin/env sh
# Resolve the newest OpenConnect release to package.
#
# OpenConnect lives on GitLab and publishes no GitHub releases. Release tags
# look like v9.21; the tarball on infradead.org can trail the tag briefly, so
# only report a version whose tarball is already downloadable.
set -eu

TAGS=$(curl -fsS 'https://gitlab.com/api/v4/projects/openconnect%2Fopenconnect/repository/tags?per_page=100' |
	grep -o '"name":"v[0-9]*\.[0-9]*"' | sed -E 's/^"name":"v([0-9.]+)"$/\1/' | sort -rV)

for version in $TAGS; do
	if curl -sfI "https://www.infradead.org/openconnect/download/openconnect-${version}.tar.gz" >/dev/null 2>&1; then
		printf '%s\n' "$version"
		exit 0
	fi
done

echo "no downloadable OpenConnect release found" >&2
exit 1

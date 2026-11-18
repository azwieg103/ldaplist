#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work"; TOP="$ROOT/rpmbuild"; DIST="$ROOT/dist"
VERSION="$(sed -n 's/^#define VERSION "\([^"]*\)"/\1/p' "$ROOT/src/ldaplist.c")"
RELEASE="${RPM_RELEASE:-ZWIEGNET.1.el10}"
[[ -n "$VERSION" && "$RELEASE" =~ ^ZWIEGNET\.[1-9][0-9]*\.el10$ ]]
for c in gcc make rpmbuild tar pkg-config; do command -v "$c" >/dev/null; done
pkg-config --exists ldap libsasl2
rm -rf "$WORK" "$TOP" "$DIST"
mkdir -p "$WORK/ldaplist" "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$DIST"
cp -a "$ROOT/Makefile" "$ROOT/src" "$ROOT/man" "$ROOT/LICENSE" "$WORK/ldaplist/"
tar -czf "$TOP/SOURCES/ldaplist-$VERSION.tar.gz" -C "$WORK" ldaplist
rpmbuild -ba "$ROOT/packaging/ldaplist.spec" --define "_topdir $TOP" --define "ldaplist_version $VERSION" --define "ldaplist_release $RELEASE"
find "$TOP/RPMS" "$TOP/SRPMS" -type f -name '*.rpm' -exec cp -v {} "$DIST/" \;
find "$DIST" -maxdepth 1 -type f -printf '%f\n' | sort

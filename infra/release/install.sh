#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install Kotton from this unpacked archive.
#
# It copies files and makes two links, and does nothing else: no network, no
# account, no key, no service registered with the system. Run it again from a
# newer archive to upgrade; your identity and your things live elsewhere (the
# base directory, `kotton config paths`) and are not touched.
#
#   sh install.sh                      into ~/.local/opt/kotton, links in ~/.local/bin
#   KOTTON_PREFIX=/some/dir sh install.sh
#
# Written for `cargo xtask release` (TASK-a-friend-cannot-install-kotton-without-a-toolchain).
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
: "${HOME:?HOME is not set, so there is nowhere to install to — set KOTTON_PREFIX and KOTTON_BINDIR}"
prefix=${KOTTON_PREFIX:-"$HOME/.local/opt/kotton"}
bindir=${KOTTON_BINDIR:-"$HOME/.local/bin"}

# Replace only what an earlier install made. A prefix that exists and is not
# one of ours is somebody else's directory, and this script does not delete it.
if [ -e "$prefix" ] && [ ! -f "$prefix/REVISION" ]; then
    echo "install: $prefix exists and is not a Kotton install — nothing was changed." >&2
    echo "  Choose another: KOTTON_PREFIX=/some/empty/dir sh install.sh" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$prefix")"
staging="$prefix.installing"
rm -rf "$staging"
mkdir "$staging"
# LICENSE and NOTICES are Kotton's own terms, and THIRD-PARTY-NOTICES everyone
# else's: the prefix keeps all three, so what is installed says what it is under.
cp -R "$here/bin" "$here/kotton-start" "$here/REVISION" \
    "$here/THIRD-PARTY-NOTICES" "$here/LICENSE" "$here/NOTICES" "$staging/"
if [ -e "$prefix" ]; then
    rm -rf "$prefix.previous"
    mv "$prefix" "$prefix.previous"
fi
mv "$staging" "$prefix"
rm -rf "$prefix.previous"

mkdir -p "$bindir"
ln -sf "$prefix/bin/kotton" "$bindir/kotton"
ln -sf "$prefix/kotton-start" "$bindir/kotton-start"

echo "Kotton $(sed -n 1p "$prefix/REVISION") is installed in $prefix."
echo
echo "  kotton-start              start the daemon in this terminal, and leave it running"
echo "  kotton id create <name>   then, from another terminal: make your identity"
echo "  kotton                    and enter Kotton's shell as it"
echo "  kotton --help             everything else"
case ":${PATH:-}:" in
    *":$bindir:"*) ;;
    *) echo; echo "  $bindir is not on your PATH; add it, or run $prefix/kotton-start directly." ;;
esac

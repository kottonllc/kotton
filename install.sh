#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install Kotton from the release this checkout is at.
#
#   git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton && sh kotton/install.sh
#
#   sh kotton/install.sh                  this machine's desktop: into ~/.local/opt/kotton,
#                                         kotton and kotton-start linked into ~/.local/bin
#   sh kotton/install.sh --kind relay     as root, on a host: the relay, under systemd
#   sh kotton/install.sh --kind vault     as root, on a host: the vault, under systemd
#   sh kotton/install.sh --kind host      as root, on a host: the relay and the vault, both
#   sh kotton/install.sh --dry-run        say what it would download, and download nothing
#
# What it does, in order, and it stops at the first thing that is not so:
#
#   1. reads the release from the checkout: the `v*` tag HEAD is at, and the commit that
#      tag names, whose first twelve characters name the release's archives;
#   2. downloads SHA256SUMS and SHA256SUMS.sig from that tag's release, and checks the
#      signature with `ssh-keygen -Y verify` against infra/release/allowed_signers as the
#      tag holds it — read from git, never from the working copy and never from a download;
#   3. downloads the archive for this machine and checks it against SHA256SUMS;
#   4. unpacks it in a directory of its own, and runs the archive's own install.sh, which
#      says what it put where and what to type next.
#
# Nothing is downloaded before the checkout is at a tag, and nothing is unpacked before both
# checks pass. A release with no SHA256SUMS.sig has not been signed, and nothing from it runs.
#
# Everything the archive's install.sh reads from the environment reaches it: KOTTON_PREFIX
# and KOTTON_BINDIR for the desktop; KOTTON_OPERATOR_KEY and KOTTON_PUBLIC_ADDR for a relay or
# a vault; KOTTON_OPERATOR_KEY_RELAY, KOTTON_OPERATOR_KEY_VAULT, KOTTON_HOST_KINDS and
# KOTTON_PUBLIC_ADDR for a host. It is also told how it was reached (KOTTON_INSTALL_COMMAND), so
# a line it prints to run again names this script, which stays, and not its own path in the
# directory this one removes.
# KOTTON_RELEASE_BASE replaces https://github.com/kottonllc/kotton/releases/download, under
# which the release is <base>/<tag>/; it moves where the bytes come from and nothing else,
# since the key that judges them is the checkout's.
#
# This is the checkout's installer. The archive's own is infra/release/install.sh (the
# desktop's) or infra/release/install-server.sh (a host's), packed into each archive as
# install.sh by `cargo xtask release` and `cargo xtask release-server`.
set -eu

refuse() {
    echo "install: $*" >&2
    echo "  nothing was installed." >&2
    exit 1
}

usage() {
    echo "usage: sh install.sh [--kind desktop|relay|vault|host] [--dry-run]" >&2
    exit 2
}

kind=desktop
dry_run=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --kind)
            [ "$#" -ge 2 ] || usage
            kind=$2
            shift 2
            ;;
        --kind=*)
            kind=${1#--kind=}
            shift
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        -h | --help)
            sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) usage ;;
    esac
done
case "$kind" in
    desktop) prefix=kotton ;;
    relay | vault | host) prefix=kotton-$kind ;;
    *) refuse "--kind is desktop|relay|vault|host, not '$kind'" ;;
esac

for tool in git curl ssh-keygen sha256sum tar mktemp; do
    command -v "$tool" >/dev/null 2>&1 || refuse "$tool is not on this machine, and the release cannot be fetched and checked without it"
done

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# 1. The release, from the checkout. git's own words when it cannot read the checkout at all
# (not one, or one owned by another user), since they name the fix.
if ! said=$(git -C "$here" rev-parse --show-toplevel 2>&1); then
    refuse "git cannot read the checkout at $here: $said"
fi
tag=$(git -C "$here" describe --tags --exact-match --match 'v*' HEAD 2>/dev/null) ||
    refuse "this checkout is not at a release tag, so there is no release to install — clone one: git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton"
rev=$(git -C "$here" rev-parse "$tag^{commit}" | cut -c1-12)

os=$(uname -s)
[ "$os" = Linux ] || refuse "a release is built for Linux, and this is $os"
arch=$(uname -m)
name=$prefix-$rev-linux-$arch
archive=$name.tar.gz
base=${KOTTON_RELEASE_BASE:-https://github.com/kottonllc/kotton/releases/download}/$tag
signers=infra/release/allowed_signers

if [ -n "$dry_run" ]; then
    echo "install: $tag, $archive — a dry run: nothing is downloaded or run"
    echo "  $base/SHA256SUMS"
    echo "  $base/SHA256SUMS.sig      checked against $signers at $tag"
    echo "  $base/$archive      checked against SHA256SUMS"
    echo "  then $name/install.sh, from the archive"
    exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/kotton-install.XXXXXX")
trap 'rm -rf "$work"' EXIT
# A signal ends the run through exit, so the directory goes with it: a dropped ssh session too.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The key, as the tag holds it.
git -C "$here" show "$tag:$signers" > "$work/allowed_signers" 2>/dev/null ||
    refuse "$tag holds no $signers, so nothing from its release can be checked"

fetch() {   # $1 the file, then curl's own options; curl's exit status, the file in $work
    f=$1
    shift
    (cd "$work" && curl -fL --retry 2 "$@" -o "$f" "$base/$f")
}
# The archive's progress shows at a terminal; the rest are a few hundred bytes.
show=-sS
[ ! -t 2 ] || show=--progress-bar

# 2. The sums and their signature, before the archive: an unsigned release costs no download.
echo "install: $tag, $archive"
fetch SHA256SUMS -sS || refuse "could not download $base/SHA256SUMS"
if fetch SHA256SUMS.sig -sS; then :; else
    case $? in
        22) refuse "$tag has no SHA256SUMS.sig. A release with no SHA256SUMS.sig has not been signed, and nothing from it runs." ;;
        *) refuse "could not download $base/SHA256SUMS.sig" ;;
    esac
fi
if ! said=$(ssh-keygen -Y verify -f "$work/allowed_signers" -I release@kotton -n kotton-release \
    -s "$work/SHA256SUMS.sig" < "$work/SHA256SUMS" 2>&1); then
    refuse "SHA256SUMS.sig is not a good signature by the key $signers holds at $tag, and nothing from this release runs:
  $said"
fi
echo "  $said"

# 3. The archive, against the sums the signature covers.
grep -q "^[0-9a-f]\{64\} [ *]$archive\$" "$work/SHA256SUMS" ||
    refuse "SHA256SUMS does not name $archive, so $tag has no $kind archive for linux-$arch"
fetch "$archive" "$show" || refuse "could not download $base/$archive"
if ! said=$(cd "$work" && sha256sum -c --ignore-missing SHA256SUMS 2>&1); then
    refuse "$archive is not the file SHA256SUMS names, and nothing from it runs:
  $said"
fi
echo "  $said"

# 4. Unpacked, and installed by its own install.sh.
mkdir "$work/unpacked"
tar -xzf "$work/$archive" -C "$work/unpacked" || refuse "tar could not unpack $archive"
[ -f "$work/unpacked/$name/install.sh" ] || refuse "$archive holds no $name/install.sh"
echo
# How this was reached, for the line the archive's installer prints to run again: this script
# as it was named, which stays, with its --kind. Quoted only when the name needs it.
case "$0" in
    *[!A-Za-z0-9_./-]*) self="'$0'" ;;
    *) self=$0 ;;
esac
KOTTON_INSTALL_COMMAND="sh $self --kind $kind"
export KOTTON_INSTALL_COMMAND
sh "$work/unpacked/$name/install.sh"

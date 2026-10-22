#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install a Kotton host — the relay and the vault, on one machine — from this unpacked archive.
#
# Packed into the host archive as `install.sh` by `cargo xtask release-server host`. The
# archive holds the relay's archive tree under relay/ and the vault's under vault/, each with
# its own install.sh (infra/release/install-server.sh), and this runs those two, one after the
# other. Each still checks its own files, makes its own user, places its own binary, unit and
# settings, and creates its own instance; this adds four things:
#
#   - one key each: KOTTON_OPERATOR_KEY_RELAY for the relay and KOTTON_OPERATOR_KEY_VAULT for
#     the vault, the two `mint host` printed. A single KOTTON_OPERATOR_KEY is refused, and so
#     are two equal keys: one key never operates two instances;
#   - one address question: the first install asks it as it always does, and the address it
#     was given is handed to the second, which then asks nothing;
#   - as root on the host itself, both started under systemd, now and at every boot, or
#     restarted on an upgrade;
#   - one line back: the relay's line and the vault's, one space between, on one row, which
#     `kotton enrol` reads as the two lines it is. It is the last output.
#
#   KOTTON_OPERATOR_KEY_RELAY=<key> KOTTON_OPERATOR_KEY_VAULT=<key> sh install.sh
#                                         as root, on the host: installs both, creates each
#                                         for its key, starts both, prints the host's line
#   sh install.sh                         an upgrade: installs both, creates nothing, and
#                                         restarts both
#   KOTTON_HOST_KINDS=relay sh install.sh only the relay, or only the vault; relay,vault, the
#                                         default, is both
#   KOTTON_PUBLIC_ADDR=<ip> sh install.sh the host's one address, written for both; nothing is
#                                         asked
#   KOTTON_ROOT=/some/dir sh install.sh   every file under /some/dir instead of /, and
#                                         systemd is not asked to start anything
#
# What SHA256SUMS proves is that these files are the ones the archive was packed with. It does
# not prove who packed it: the checkout's install.sh checks the archive against the release's
# signed sums before it is unpacked.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=${KOTTON_ROOT:-}
cd "$here"

refuse() {
    echo "install: $*" >&2
    echo "  nothing was installed." >&2
    exit 1
}

# Which instances, in the one order: the relay first, so the address question, when there is
# one, is asked by the relay's install, and the vault's line comes second.
kinds=
set -f
for k in $(printf '%s' "${KOTTON_HOST_KINDS:-relay,vault}" | tr ',' ' '); do
    case "$k" in
        relay | vault) ;;
        *) refuse "KOTTON_HOST_KINDS names '$k': it is relay, vault, or relay,vault" ;;
    esac
    case " $kinds " in
        *" $k "*) refuse "KOTTON_HOST_KINDS names $k twice" ;;
    esac
    kinds="$kinds $k"
done
set +f
[ -n "$kinds" ] || refuse "KOTTON_HOST_KINDS names nothing: it is relay, vault, or relay,vault"
ordered=
for k in relay vault; do
    case " $kinds " in *" $k "*) ordered="$ordered $k" ;; esac
done
kinds=${ordered# }

# One key each, checked before anything runs, so a key cut short installs neither.
[ -z "${KOTTON_OPERATOR_KEY:-}" ] ||
    refuse "a host takes one key for each instance, KOTTON_OPERATOR_KEY_RELAY and KOTTON_OPERATOR_KEY_VAULT, as \`mint host\` printed them, and not KOTTON_OPERATOR_KEY: one key never operates two instances"
key_of() {   # $1 relay or vault: the key given for it
    case "$1" in
        relay) printf '%s' "${KOTTON_OPERATOR_KEY_RELAY:-}" ;;
        vault) printf '%s' "${KOTTON_OPERATOR_KEY_VAULT:-}" ;;
    esac
}
for k in relay vault; do
    key=$(key_of "$k")
    var=KOTTON_OPERATOR_KEY_$(printf '%s' "$k" | tr 'a-z' 'A-Z')
    [ -n "$key" ] || continue
    case " $kinds " in
        *" $k "*) ;;
        *) refuse "$var is given, and KOTTON_HOST_KINDS installs no $k" ;;
    esac
    case "$key" in
        *[!0-9a-f]*) refuse "$var is not 64 lowercase hex characters — the public key \`mint host\` printed for the $k" ;;
    esac
    [ "${#key}" -eq 64 ] || refuse "$var is ${#key} characters, not 64 — the public key \`mint host\` printed for the $k"
done
if [ -n "${KOTTON_OPERATOR_KEY_RELAY:-}" ] && [ "${KOTTON_OPERATOR_KEY_RELAY:-}" = "${KOTTON_OPERATOR_KEY_VAULT:-}" ]; then
    refuse "KOTTON_OPERATOR_KEY_RELAY and KOTTON_OPERATOR_KEY_VAULT are the same key: one key never operates two instances — \`mint host\` prints one for each"
fi

# The sums, before anything runs: this file, the notes beside it, and each instance's own
# installer and sums, which then check the rest of its tree.
[ -f SHA256SUMS ] || refuse "there is no SHA256SUMS beside install.sh"
for f in install.sh REVISION LICENSE NOTICES; do
    grep -q "  $f\$" SHA256SUMS || refuse "SHA256SUMS does not name $f"
done
for k in $kinds; do
    for f in "$k/install.sh" "$k/SHA256SUMS"; do
        grep -q "  $f\$" SHA256SUMS || refuse "SHA256SUMS does not name $f"
    done
done
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c --quiet SHA256SUMS >&2 || refuse "the files here are not the ones SHA256SUMS names"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c --quiet SHA256SUMS >&2 || refuse "the files here are not the ones SHA256SUMS names"
else
    refuse "neither sha256sum nor shasum is on this machine, so SHA256SUMS cannot be checked"
fi

# The command a line printed to run again names: the checkout's install.sh when that reached
# this, else this file, which stays where the person unpacked it. Either way with the
# instances this install makes, when they are not both.
again=${KOTTON_INSTALL_COMMAND:-}
[ -n "$again" ] || again="sh '$here/install.sh'"
[ "$kinds" = "relay vault" ] || again="KOTTON_HOST_KINDS=$(printf '%s' "$kinds" | tr ' ' ',') $again"
KOTTON_INSTALL_COMMAND=$again
export KOTTON_INSTALL_COMMAND
unset KOTTON_ADDR_ASKED KOTTON_OPERATOR_KEY

work=$(mktemp -d "${TMPDIR:-/tmp}/kotton-host.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Each instance by its own installer. Its output is the person's to read as it comes — the
# first may ask a question — and is kept, so its last line, the instance's, can be read back.
addr=${KOTTON_PUBLIC_ADDR:-}
asked=
lines=
for k in $kinds; do
    key=$(key_of "$k")
    echo "install: the $k, by $k/install.sh"
    {
        rc=0
        if [ -n "$addr" ]; then
            KOTTON_PUBLIC_ADDR=$addr KOTTON_OPERATOR_KEY=$key sh "$here/$k/install.sh" || rc=$?
        elif [ -n "$asked" ]; then
            # Asked already, and not given one: this one is not asked again.
            (unset SSH_CONNECTION && KOTTON_OPERATOR_KEY=$key sh "$here/$k/install.sh") || rc=$?
        else
            KOTTON_ADDR_ASKED="$work/answer" KOTTON_OPERATOR_KEY=$key sh "$here/$k/install.sh" || rc=$?
        fi
        echo "$rc" > "$work/rc"
    } | tee "$work/said"
    rc=$(cat "$work/rc")
    if [ "$rc" != 0 ]; then
        echo "install: the $k's install.sh failed, so the host's install stops here." >&2
        exit "$rc"
    fi
    if [ -z "$asked" ] && [ -e "$work/answer" ]; then
        asked=1
        addr=$(cat "$work/answer")
    fi
    last=$(tail -n 1 "$work/said")
    case "$last" in
        "kotton-instance:$k:"*) lines="$lines $last" ;;
    esac
    echo
done
lines=${lines# }

units=
for k in $kinds; do units="$units kotton-$k"; done
units=${units# }
if [ -z "$root" ] && [ "$(id -u)" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    failed=
    systemctl daemon-reload || failed="systemctl daemon-reload"
    for u in $units; do
        if [ -z "$failed" ]; then
            systemctl enable --quiet "$u" && systemctl restart "$u" || failed="$u"
        fi
    done
    if [ -n "$failed" ]; then
        echo "install: the files are placed, and $failed did not start: systemctl status $failed says why" >&2
    else
        echo "$units: started under systemd, now and at every boot"
    fi
else
    echo "systemd was not asked: $( [ -n "$root" ] && echo "KOTTON_ROOT is $root" || echo "this is not root on the host itself" ). On the host, as root:"
    echo "  systemctl daemon-reload && systemctl enable --now $units"
fi
# The last output: the host's line, for the desktop that minted the keys.
if [ -n "$lines" ]; then
    echo
    echo "the host's line, for your desktop — kotton enrol <this line>:"
    printf '%s\n' "$lines"
fi
[ -z "${failed:-}" ]

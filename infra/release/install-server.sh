#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install one Kotton server — the relay or the vault — from this unpacked archive.
#
# Packed into each server archive as `install.sh` by `cargo xtask release-server`
# (DEC-0085). It checks the files beside it against SHA256SUMS and refuses on any
# difference, then makes the service's user and places three things, and prints
# the systemctl lines to run:
#
#   kotton-<name>       a system user and group of that name, when the host has none:
#                       no home, no shell, no password — the unit's User= and Group=
#   bin/<binary>        -> /usr/local/bin/<binary>
#   <unit>.service      -> /etc/systemd/system/<unit>.service
#   <name>.env          -> /etc/kotton/<name>.env, the first time only, root's, mode 0600:
#                          systemd reads it as root before it runs the service as its user.
#                          The vault's, installed as root, is group kotton-vault's, 0640,
#                          because the vault's verbs read it too (below)
#
# **It creates the instance for its operator's key** (RFC-0084 V18, the amendment of
# 2026-10-01): given KOTTON_OPERATOR_KEY — the 64 hex a desktop's `mint vault` or
# `mint relay` printed, never written to any file — it makes the state directory the
# settings name, as the service's user, mode 0700, and runs the binary's `create` there
# once, as that user. Its last output is then the instance's line, which confers
# nothing. Given no key it creates nothing and says how; over state that already has an
# operator, `create` refuses and this says so. A vault or relay does not start without
# an operator, so creation is the step that makes it startable.
#
# It starts nothing, reaches no network and registers nothing with systemd;
# `systemctl` is yours to type. Run it again from a newer archive to upgrade: the
# binary and the unit are replaced, the env file you edited is not, and neither
# is anything the service keeps under /var/lib/.
#
#   KOTTON_OPERATOR_KEY=<key> sh install.sh         as root, on the host: installs, and
#                                                   creates the instance for that key
#   sh install.sh                                   an upgrade: installs, creates nothing
#   KOTTON_PUBLIC_ADDR=<ip> sh install.sh           the first install: writes the host's
#                                                   one address into the settings — the
#                                                   vault's KOTTON_PUBLIC_ADDR=<ip>, the
#                                                   relay's KOTTON_RELAY_ADVERTISE=
#                                                   http://<ip>:7700 (or fills it in a kept
#                                                   file where it is still empty)
#   sh install.sh, over ssh                         with KOTTON_PUBLIC_ADDR not given and
#                                                   that line empty: proposes the address
#                                                   the ssh session arrived at, and writes
#                                                   it on a yes at a terminal; with no
#                                                   terminal, prints the line to run instead
#   KOTTON_ROOT=/some/dir sh install.sh             every file under /some/dir instead of /;
#                                                   the user is still the system's
#
# Two settings are for the script that runs this one, and a person sets neither:
#
#   KOTTON_INSTALL_COMMAND    the command that reached this installer, which the line printed
#                             with no terminal names in place of this file's own path: the
#                             checkout's install.sh sets it to itself and its --kind, since it
#                             removes the directory this file is unpacked in when it exits, and
#                             the host's install.sh to itself, since it installs both instances
#   KOTTON_ADDR_ASKED         a file the host's install.sh names, into which this writes the
#                             answer to the address question when it asks it, the address or an
#                             empty line, so the host's second instance is not asked again
#
# What SHA256SUMS proves is that these files are the ones the archive was packed
# with. It does not prove who packed it: the archive's own sha256, printed by the
# release and checked before unpacking (docs/use/run-a-relay.md, run-a-vault.md), is what names the
# bytes the person chose.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=${KOTTON_ROOT:-}
cd "$here"

refuse() {
    echo "install: $*" >&2
    echo "  nothing was installed." >&2
    exit 1
}

# Exactly one of each, so the archive says which server it is and nothing here does.
one() {   # $1 what, then the glob's matches
    what=$1
    shift
    [ "$#" -eq 1 ] && [ -f "$1" ] || refuse "this archive holds no single $what (found: $*)"
    printf '%s\n' "$1"
}
unit=$(one "systemd unit" ./*.service)
unit=${unit#./}
env=$(one "env file" ./*.env)
env=${env#./}
bin=$(one "binary" bin/*)
name=${env%.env}
binary=${bin#bin/}

# The sums, before anything is copied. Every file this places, and the notes
# beside it — everyone else's licenses and Kotton's own — must be named in
# SHA256SUMS and match it.
[ -f SHA256SUMS ] || refuse "there is no SHA256SUMS beside install.sh"
for f in "$bin" "$unit" "$env" install.sh REVISION THIRD-PARTY-NOTICES LICENSE NOTICES; do
    grep -q "  $f\$" SHA256SUMS || refuse "SHA256SUMS does not name $f"
done
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c --quiet SHA256SUMS >&2 || refuse "the files here are not the ones SHA256SUMS names"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c --quiet SHA256SUMS >&2 || refuse "the files here are not the ones SHA256SUMS names"
else
    refuse "neither sha256sum nor shasum is on this machine, so SHA256SUMS cannot be checked"
fi

# The operator's key, when given: checked before anything is placed, so a key cut short
# installs nothing. It is a public key, and it is written to no file here — `create`
# records it in the instance's own operator set, and nowhere else.
key=${KOTTON_OPERATOR_KEY:-}
if [ -n "$key" ]; then
    case "$key" in
        *[!0-9a-f]*) refuse "KOTTON_OPERATOR_KEY is not 64 lowercase hex characters — the public key \`mint $name\` printed" ;;
    esac
    [ "${#key}" -eq 64 ] || refuse "KOTTON_OPERATOR_KEY is ${#key} characters, not 64 — the public key \`mint $name\` printed"
fi

# The host's one address, when given: checked before it is written, because a
# URL is made from it. An IPv6 address needs brackets in that URL; write the
# lines by hand for one.
addr=${KOTTON_PUBLIC_ADDR:-}
case "$addr" in
    *[!A-Za-z0-9.-]*) refuse "KOTTON_PUBLIC_ADDR '$addr' is not a hostname or an IPv4 address — for IPv6, install without it and edit $env by hand" ;;
esac

# Where the settings go.
settings="$root/etc/kotton/$env"

# The settings have three readers: systemd's EnvironmentFile=, for the unit; this
# installer, for what it hands `create` and whether it may fill the address; and, for
# the vault, kvaultd itself, which reads vault.env before every verb but `serve`
# (kvaultd::settings::env_file_pairs). Readers of one file that disagree are a defect each
# time they meet — a kept value's quotes reached the relay's line, an indented line read
# as unset here was overridden by the line added after it, a quoted vault address reached
# `create` with its quotes. So no reader chases systemd's grammar: each reads one plain
# form, which systemd reads the same, and this installer refuses a file holding anything
# else, before it writes anything. Every line is blank, a comment — `#` or `;` first,
# after any blanks — or
#   KEY=value    KEY="value"    KEY='value'
# at the start of the line: the key a name, no space around =, the value printable ASCII
# with no quote or backslash inside, an unquoted one neither starting nor ending in a
# space, a quoted one closed by the line's last character. Each narrowing has a measured
# cause, checked against systemd 255's own load_env_file by the settings differential:
#   - printable ASCII: invalid UTF-8 in any assignment makes load_env_file fail the whole
#     file, so the unit would not start;
#   - quotes only as one pair around a value: systemd runs a quoted value across newlines,
#     and opens another run at a quote right after a closing one, so the lines such a run
#     spans set nothing; a quote anywhere else it reads literally, and is refused anyway;
#   - no backslash in a value: systemd reads one inside double quotes as an escape.
# And on every line, comments included: no line ends in a backslash (systemd continues a
# setting through one into the next line even when that line looks like a comment, and
# before v254 continues a comment through one), and — checked first, file-wide — no NUL
# and no carriage return. Read byte by byte: mawk matches bytes in any locale, but gawk
# under a UTF-8 locale matches by character, and LC_ALL=C keeps the check byte-wise on both.
file_form() {   # $1 the file; prints "<line number> <what is wrong>" of the first line refused
    LC_ALL=C awk '
        BEGIN {
            q = "\"\047"
            bare = "[^" q "\\\\ ]"
            body = "[^" q "\\\\]"
            plain = "^[A-Za-z_][A-Za-z0-9_]*=(\"" body "*\"|\047" body "*\047|" bare "(" body "*" bare ")?)?$"
        }
        /\\$/ { print NR " ends in a backslash, which joins the next line onto it"; exit }
        /^[ \t]*$/ { next }
        /^[ \t]*[#;]/ { next }
        /[^ -~]/ { print NR " holds a byte that is not printable ASCII"; exit }
        $0 !~ plain { print NR " is not a comment nor a setting in the plain form KEY=value, KEY=\"value\" or KEY=\047value\047: " $0; exit }
    ' "$1"
}

# Why this installer refuses a settings file, or nothing when it reads it as systemd does:
# the one function every check above runs through, so the tests that hold it against
# systemd's own parser call exactly what an install calls.
settings_refusal() {   # $1 the file; prints the refusal, nothing when the file is read
    # A NUL anywhere, on any line, a comment's included: systemd's parser walks the file as
    # a C string and stops at the first one, so every setting after it is hidden from the
    # unit while this reader reads on. Found by counting the file's bytes with and without
    # its NULs (tr and wc, coreutils on any host); cmp, where there is one, names the line
    # of the first difference, the line holding the first NUL.
    if [ "$(tr -d '\000' < "$1" | wc -c)" -ne "$(wc -c < "$1")" ]; then
        at=$(tr -d '\000' < "$1" | LC_ALL=C cmp "$1" - 2>&1 | sed -n 's/.*line \([0-9][0-9]*\).*/ line \1/p')
        printf '%s\n' "$1$at holds a NUL byte, where systemd stops reading the file and this installer would read on
  remove it and run install.sh again. The file is unchanged."
        return
    fi
    # A carriage return anywhere, a comment's included: systemd reads one as a line break,
    # so a comment ends there and what follows it on the line is read as a setting this
    # installer, reading lines by newline, would not see. A CRLF file is refused by this too.
    cr=$(LC_ALL=C awk '/\r/ { print NR; exit }' "$1")
    if [ -n "$cr" ]; then
        printf '%s\n' "$1 line $cr holds a carriage return, which systemd reads as a line break and this installer does not
  remove it (save the file with plain newlines) and run install.sh again. The file is unchanged."
        return
    fi
    wrong=$(file_form "$1")
    if [ -n "$wrong" ]; then
        printf '%s\n' "$1 line ${wrong%% *} ${wrong#* }, so systemd would read this file otherwise than this installer
  rewrite it as KEY=<value>, KEY=\"<value>\" or KEY='<value>' — at the start of the line, no space around = or after the value, printable ASCII with no quote or backslash in the value — or as a comment, end no line in a backslash, and run install.sh again. The file is unchanged."
        return
    fi
}
for file in "$env" "$settings"; do
    [ -e "$file" ] || continue
    why=$(settings_refusal "$file")
    [ -z "$why" ] || refuse "$why"
done

# One value of the settings, in the plain form above: the last line that sets it wins,
# as it does for systemd, and one matching pair of quotes around the value is not part
# of it. Everything this installer reads from the settings is read here.
setting() {   # $1 the variable, $2 the file; prints its value, empty when no line sets it
    v=$(sed -n "s|^$1=||p" "$2" | tail -n 1)
    case "$v" in
        \"*\") v=${v#\"}; v=${v%\"} ;;
        \'*\') v=${v#\'}; v=${v%\'} ;;
    esac
    printf '%s' "$v"
}
# The settings as they will be: the kept file, or the archive's when there is none.
current() {
    if [ -e "$settings" ]; then printf '%s' "$settings"; else printf '%s' "$env"; fi
}

# The line of the settings that address goes into, and as what. The vault's is
# KOTTON_PUBLIC_ADDR, the address itself. The relay's is KOTTON_RELAY_ADVERTISE, the
# URL it is reached at on the port it binds (KOTTON_RELAY_BIND; the port table's 7700/tcp,
# infra/README.md, when that names none): what it signs at GET /identity and the hint its
# line carries, so the line `create` prints names where the relay is
# (TASK-the-installer-tells-the-relay-the-address-it-announces).
case "$name" in
    vault) addr_var=KOTTON_PUBLIC_ADDR ;;
    *)
        addr_var=KOTTON_RELAY_ADVERTISE
        port=$(setting KOTTON_RELAY_BIND "$(current)")
        port=${port##*:}
        case "$port" in "" | *[!0-9]*) port=7700 ;; esac
        ;;
esac
addr_value() {   # $1 the host's address
    case "$name" in
        vault) printf '%s' "$1" ;;
        *) printf 'http://%s:%s' "$1" "$port" ;;
    esac
}

# Whether the address is still to be written: the settings are not there yet, or a kept
# file sets it to nothing — an empty line, or no line at all, which is every relay.env
# from before the relay's had one, and which systemd reads the same. A value a person
# set is never replaced.
unset_addr() {
    [ ! -e "$settings" ] || [ -z "$(setting "$addr_var" "$settings")" ]
}

# Not given it, the installer proposes the address this ssh session arrived at — the third
# field of $SSH_CONNECTION (TASK-the-vault-installer-writes-an-empty-address-when-the-ssh-session-knows-it).
# It proposes and does not decide: behind NAT or on a floating IP, devices outside dial
# another address. So it is written only on a yes typed at a terminal; with none, the
# line that writes it is printed, and nothing is written for it.
if [ -z "$addr" ] && [ -n "${SSH_CONNECTION:-}" ] && unset_addr; then
    set -f
    set -- $SSH_CONNECTION   # client_ip client_port server_ip server_port
    set +f
    seen=${3:-}
    asked=
    case "$seen" in
        *:*)
            printf 'install: this ssh session arrived at %s, an IPv6 address, which this installer does not write:\n' "$seen"
            echo "  set $addr_var in $settings by hand."
            asked=1
            ;;
        "" | *[!0-9.]*) ;;
        *)
            case "$seen" in
                127.*) kind=" — a loopback address, which no other machine reaches" ;;
                10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].* | 169.254.* | \
                    100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7].*)
                    kind=" — a private address, which devices outside this network do not reach" ;;
                *) kind= ;;
            esac
            asked=1
            echo "install: KOTTON_PUBLIC_ADDR is not set. This ssh session arrived at $seen$kind."
            echo "  it is the address devices dial only if nothing between them and here (NAT, a floating IP) changes it."
            if [ -t 0 ]; then
                printf '  write %s=%s into %s? [y/N] ' "$addr_var" "$(addr_value "$seen")" "$settings"
                answer=
                read -r answer || answer=
                case "$answer" in
                    y | Y | yes | YES | Yes) addr=$seen ;;
                    *) echo "  not written." ;;
                esac
            else
                echo "  there is no terminal to ask at, so nothing is written for it. To write it, run:"
                if [ -n "${KOTTON_INSTALL_COMMAND:-}" ]; then
                    printf '    KOTTON_PUBLIC_ADDR=%s %s\n' "$seen" "$KOTTON_INSTALL_COMMAND"
                else
                    printf "    KOTTON_PUBLIC_ADDR=%s sh '%s'\n" "$seen" "$0"
                fi
            fi
            ;;
    esac
    if [ -n "$asked" ] && [ -n "${KOTTON_ADDR_ASKED:-}" ]; then
        printf '%s\n' "$addr" > "$KOTTON_ADDR_ASKED"
    fi
fi

# The service's own user: the unit names it, systemd runs the binary as it and makes
# the state directory its. Made only by root, and only when absent, so an install run twice makes it once.
user=kotton-$name
if [ "$(id -u)" = 0 ]; then
    if ! getent passwd "$user" >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --home-dir "/var/lib/$user" \
            --shell /usr/sbin/nologin --comment "Kotton $name" "$user" ||
            refuse "useradd could not make the user $user"
        made="made now"
    else
        made="already on this host"
    fi
elif [ -n "$root" ]; then
    made="not made — this install ran as $(id -un), not root"
else
    refuse "run it as root: it writes /usr/local/bin and /etc, and makes the user $user"
fi

install -d "$root/usr/local/bin" "$root/etc/systemd/system" "$root/etc/kotton" "$root/usr/local/share/kotton-$name"

# The binary is replaced in one rename, so a running service's next start never
# finds half a file.
install -m 0755 "$bin" "$root/usr/local/bin/.$binary.installing"
mv -f "$root/usr/local/bin/.$binary.installing" "$root/usr/local/bin/$binary"
install -m 0644 "$unit" "$root/etc/systemd/system/$unit"
install -m 0644 REVISION "$root/usr/local/share/kotton-$name/REVISION"

# The address goes only where the settings set it to nothing — an empty line, or none,
# when it is added — so a value a person set in a kept file is never replaced. No relay is written into the vault's: a vault
# stands where its owner's desktop tells it
# (TASK-the-desktop-tells-the-vault-which-relays-to-stand-at).
fill() {   # $1 the settings to copy, with the address written where it is empty
    value=$(addr_value "$addr")
    if grep -q "^$addr_var=" "$1"; then
        (umask 077 && sed -e "s|^$addr_var=\$|$addr_var=$value|" \
            -e "s|^$addr_var=\"\"\$|$addr_var=$value|" \
            -e "s|^$addr_var=''\$|$addr_var=$value|" \
            "$1" > "$settings.installing")
    else
        # No line sets it — a file from before it had one, or one whose line is commented
        # out — so it is added last, where it is the line systemd reads.
        (umask 077 && cat "$1" > "$settings.installing" &&
            printf '\n# Added by install.sh: the address this %s announces.\n%s=%s\n' "$name" "$addr_var" "$value" >> "$settings.installing")
    fi
    chmod 0600 "$settings.installing"
    mv -f "$settings.installing" "$settings"
}
if [ -e "$settings" ] && [ -n "$addr" ] && unset_addr; then
    fill "$settings"
    wrote="kept, its unset $addr_var set to $(addr_value "$addr")"
elif [ -e "$settings" ]; then
    wrote="kept — an install never overwrites it"
    [ -z "$addr" ] || echo "install: $settings exists, so $addr_var=$(addr_value "$addr") was not written; edit the file to change it." >&2
elif [ -n "$addr" ]; then
    fill "$env"
    wrote="written now"
else
    (umask 077 && cp "$env" "$settings.installing")
    chmod 0600 "$settings.installing"
    mv -f "$settings.installing" "$settings"
    wrote="written now"
fi
# Who may read it. The vault's verbs at the host's shell — `kvaultd invite`, `tenants`
# and the rest — read vault.env themselves, as the unit's EnvironmentFile= gives it to
# the daemon, and are typed as root or as the vault's own user; so on a host the vault's
# file is group kotton-vault's to read, 0640. That user is handed every value in it by
# systemd at each start, so reading the file reaches nothing it does not already hold.
# The relay's stays 0600: nothing run as its user reads it. The owner and mode are the
# installer's and are set at every install, on a kept file too; the content is yours.
# A group of that name the host already had, with members of its own, would hand
# them the file too; then it stays root's alone and says so.
members=$(getent group "$user" 2>/dev/null | cut -d: -f4)
if [ "$name" = vault ] && [ "$(id -u)" = 0 ] && [ -n "$members" ]; then
    chmod 0600 "$settings"
    wrote="$wrote, mode 0600: the group $user has other members ($members), so the vault's verbs work as root only"
elif [ "$name" = vault ] && [ "$(id -u)" = 0 ]; then
    if ! chgrp "$user" "$settings"; then
        echo "install: chgrp could not give $settings to the group $user; it is left 0600, root's alone." >&2
        echo "  the binary and the unit are placed; fix the group and run install.sh again." >&2
        exit 1
    fi
    chmod 0640 "$settings"
    wrote="$wrote, mode 0640, group $user"
else
    chmod 0600 "$settings"
    wrote="$wrote, mode 0600"
fi

# The instance, created for its operator's key. Its state directory is the one the
# settings name — KOTTON_BASE_DIR for the vault, KOTTON_RELAY_STATE_DIR for the relay, or the
# unit's /var/lib/kotton-<name> when a kept file names neither — under KOTTON_ROOT; made here, before the first start, where systemd's StateDirectory=
# made it at that start, because creation needs it first. Made and written as the
# service's user, so nothing in it is root's.
case "$name" in
    vault) state_var=KOTTON_BASE_DIR ;;
    *) state_var=KOTTON_RELAY_STATE_DIR ;;
esac
state_dir=$(setting "$state_var" "$settings")
# A kept file that names none: the directory the unit's StateDirectory= names.
state_dir=${state_dir:-/var/lib/$user}
state="$root$state_dir"
as_service() {   # the command, as the service's user when this is root
    if [ "$(id -u)" = 0 ]; then
        runuser -u "$user" -- "$@"
    else
        "$@"
    fi
}
created=
if [ -n "$key" ]; then
    install -d -m 0700 "$state"
    if [ "$(id -u)" = 0 ]; then
        chown "$user:$user" "$state" || refuse "chown could not give $state to $user"
    fi
    # The relay is told the address its settings announce, as the unit tells it at
    # every start, so the line `create` prints names it. The vault's `create` reads
    # vault.env itself, beside its installed binary; the relay's user cannot read
    # relay.env, root's 0600, so the value is read here and handed over.
    case "$name" in
        vault) set -- "$root/usr/local/bin/$binary" create --state-dir "$state" --operator "$key" ;;
        *)
            advertise=$(setting KOTTON_RELAY_ADVERTISE "$settings")
            set -- "$root/usr/local/bin/$binary" --state-dir "$state" --advertise "$advertise" create --operator "$key"
            ;;
    esac
    if said=$(as_service "$@" 2>&1); then
        created=$(printf '%s\n' "$said" | tail -n 1)
    else
        case "$said" in
            *"has an operator"*) creation="nothing created: $state already holds a $name that has an operator; it prints its line at its next start" ;;
            *) printf 'install: the %s was not created:\n%s\n' "$name" "$said" >&2
               echo "  the binary, the unit and the settings are placed; fix that and run install.sh again." >&2
               exit 1 ;;
        esac
    fi
elif [ -e "$state" ]; then
    creation="nothing created: $state is kept; a $name whose state names no operator does not start, and KOTTON_OPERATOR_KEY=<key> sh install.sh adopts it"
else
    creation="nothing created: the $name does not start until it is created for its operator's key — run this again as KOTTON_OPERATOR_KEY=<the 64 hex \`mint $name\` printed> sh install.sh"
fi

service=${unit%.service}
echo "$service $(sed -n 1p REVISION) is installed:"
echo "  user $user ($made)"
echo "  $root/usr/local/bin/$binary"
echo "  $root/etc/systemd/system/$unit"
echo "  $settings ($wrote)"
if [ -n "$created" ]; then
    echo "  $state (created for the operator's key, as $user)"
else
    echo "  $creation"
fi
if [ -z "$(setting "$addr_var" "$settings")" ]; then
    echo
    echo "  $addr_var is not set in $settings: set it before starting."
fi
echo
echo "next, as root:"
echo "  systemctl daemon-reload"
echo "  systemctl enable --now $service     # the first install"
echo "  systemctl restart $service          # an upgrade"
# The last output: the instance's line, for the desktop that minted the key.
if [ -n "$created" ]; then
    echo
    echo "the $name's line, for your desktop:"
    printf '%s\n' "$created"
fi

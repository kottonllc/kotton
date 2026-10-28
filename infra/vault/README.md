# kotton-vault — reference

A **vault** keeps a person's data, sealed before it arrives, and cannot open any of it. It
admits their devices, keeps the one sealed packet a phrase-only device needs to find its way
back, and reserves at their relay so they are reachable when nothing of theirs is awake. It
is paid by the byte, it has one meter, and one process keeps for many people. What is *not*
in the binary is the point — no apps, no sandbox, no display, no plaintext verb — and
`cargo xtask vault-check` holds the dependency list to that.

The design is [Nodes](../../docs/design/nodes.md).
**Anyone can run one**, and nothing is held back from the repository to do it.

**To set one up, read the guide, not this:** [Run a vault](../../docs/use/run-a-vault.md), and
[the index](../../docs/use/README.md) for everything before and after it. This file describes
the files beside it.

---

## The files here

| File | On the host | What it is |
| --- | --- | --- |
| [`kotton-vault.service`](kotton-vault.service) | `/etc/systemd/system/` | the unit: runs `/usr/local/bin/kvaultd` as `kotton-vault`, never root; systemd makes `/var/lib/kotton-vault` and `/run/kotton-vault` for that user, mode 0700; ordered after a relay on the same host and does not require one |
| [`vault.env`](vault.env) | `/etc/kotton/vault.env` | every setting below; placed once by `install.sh`, never overwritten, root's and the group `kotton-vault`'s, mode 0640 — systemd reads it as root and hands every value to the vault's user, and the verbs below read it as either |
| [`docker-compose.yml`](docker-compose.yml) | — | the scenarios' form of the same environment; **not how a host runs it** |

`cargo xtask release-server vault` packs the first two with the binary, `install.sh`,
`REVISION` and `SHA256SUMS`. Edit `/etc/kotton/vault.env`, then `systemctl restart kotton-vault`.

## Settings

| Variable | In `vault.env` | What it is |
| --- | --- | --- |
| `KOTTON_PUBLIC_ADDR` | empty | the host's one address: what a device dials, the vault announces in the ceremony, and its owner's desktop first reaches it at. `KOTTON_PUBLIC_ADDR=<ip> sh install.sh` writes it on the first install. A vault with none is not on 0.1's path |
| `KOTTON_BASE_DIR` | `/var/lib/kotton-vault` | everything it keeps |
| `KOTTON_PEER_LISTEN_PORT` | `7710` | UDP, where devices reach it — the [port table](../README.md)'s |
| `KVAULTD_QUOTA_BYTES` | `0` | the number a pool starts with when its invite set none; `0` or unset is none. A pool with its own number ignores a change here |
| `KVAULTD_SHELF` | `local` | where pools rest: `local` (`KOTTON_BASE_DIR`) or `s3` |
| `KVAULTD_S3_ENDPOINT`, `_BUCKET`, `_REGION`, `_PREFIX` | empty; region `us-east-1` | an S3-compatible bucket — MinIO, Garage, Ceph, AWS. Path-style requests; the bucket must exist; pools live under `<prefix>/<person>/local/` |
| `KVAULTD_S3_ACCESS_KEY`, `_SECRET_KEY` | empty | a secret, which is why the file is 0640 and no one's but root's and the vault's user's. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are read when these are absent |
| `KOTTON_SECRETS` | `file` | a host has no keychain: the vault's key is a 0600 file under `KOTTON_BASE_DIR` |
| `KVAULTD_IPC_NAME`, `XDG_RUNTIME_DIR` | `vault`, `/run/kotton-vault` | the door's name and the directory it is made in |
| `RUST_LOG`, `NO_COLOR` | `info`, `1` | the journal's level; plain text in it |

**Keep `vault.env` in its plain form.** Three things read this file — the installer, systemd when
it starts the vault, and every `kvaultd` verb, which reads it before it runs — and they agree
because each reads one plain form. Every line is blank, a comment (`#` or `;` first, after any
blanks), or a setting written as `KEY=value`, `KEY="value"` or `KEY='value'`: at the start of the
line, no space around `=` or after the value, nothing but printable ASCII in it, no quote or
backslash inside the value, and quotes only as one pair around all of it. No line, a comment
included, ends in a backslash or holds a carriage return, and the file holds no NUL byte. A file
with any other line is refused before anything is placed, naming the file, the line and the form
to rewrite it in, and a `kvaultd` verb given one refuses too, naming the line. Each rule has a
measured cause in systemd's own parser: it fails the whole file on invalid UTF-8 in a setting;
it runs a quoted value across lines, and opens another at a quote right after a closing one; it
reads a backslash inside double quotes as an escape; it continues a setting through a trailing
backslash into the next line even when that line looks like a comment, and before v254 continues
a comment through one too; it reads a carriage return as a line break, even inside a comment;
and it stops reading at a NUL.

**No relay is set here.** A vault stands where its owner's desktop tells it — `enrol <its line>`
on the desktop, once it operates the relay — and keeps that reach set in its own state, so a
restart needs no desktop and an install that rewrites this file yields the same vault
(`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`,
RFC-0084 V12). A `KOTTON_RELAY_URL` line from an earlier install is not read, and the vault
says so once in its journal at start.

On a bucket, what stays on the vault's own disk is small and its own: its key, each person's
identity chain and sealed recovery copy, and who is paired. A person's device is told a number
of bytes, the same whichever shelf is beneath.

## The verbs at the door

Typed at the host's shell, as root or as `kotton-vault`:

```sh
kvaultd tenants
```

Each verb reads `/etc/kotton/vault.env` itself — the file beside the binary `install.sh`
placed — so it looks for the door where the file told the vault to make it. With no vault
running it says so in one sentence. `KVAULTD_IPC_NAME` in the environment names another
door, and then the file is not read.

| Verb | Does |
| --- | --- |
| `invite <user> [--quota <bytes>] [--ttl <seconds>]` | mints an invite at the relay — its URL and three words — and waits (a day by default) for `drive enrol <invite>`. A name already kept is refused |
| `join <user> <code>` | the vault dials instead, for a device on its own network running `device add --blind` |
| `tenants` | everyone kept for: name, bytes held, quota, how many devices paired — never a device's name or a key |
| `capacity <user> [--set <bytes>]` | one person's bytes and number; `--set` changes it while it runs. Lower than what is held deletes nothing: the next write is refused |
| `drop <user> [--yes]` | removes that one person's pool, chain, recovery copy, pairings and quota, after their name is typed back; nobody else's |
| `create --state-dir <dir> --operator <key>` | creates the vault for its operator's key, once, before it serves — `install.sh` runs it as `kotton-vault` when given `KOTTON_OPERATOR_KEY`: the vault's own key, the key given as its first operator, and the vault's line as the last output, `kotton-instance:vault:<its key>@<address:port>`. Over a vault that has an operator it refuses and changes nothing; over older state that names none it adopts it, keeping its key and its tenants; it never makes a key over existing state. A vault with no operator refuses to start and names this; every start prints the line again, and it confers nothing |
| `operator enrol <key>` · `operator revoke <key>` · `operator revoke --all --keep <key>` | the operator credential's public half: its acts (invite and the six digits an invite's device asks for, tenants, space, drop) said from a desktop's `vault` verb, under a key of the vault's own (the relay's is another, DEC-0087). Prints the vault's line for the desktop's `enrol <line>`, and says where the vault stands — nowhere until its desktop tells it. Said at the running vault's door; there is no offline enrol. The last operator is never revoked: `--all --keep` names the one that stays |

A payload carrying a key is refused before anything is written, so `device add` without
`--blind` fails here by design. **Who may reach the door is your policy:** it is in
`/run/kotton-vault`, mode 0700, so root and the vault's user reach it and no one else does.

## What you keep, stated plainly

The tenant is on the lease: you hold their identity chain, a byte count, and the times it
changes. A warrant to you yields those three things and nothing that can be read. A person who
leaves admits a vault elsewhere, and you are not asked
(`a_person_moves_vaults_and_the_first_landlord_is_never_asked`, `tests/tests/suite/vault.rs`).

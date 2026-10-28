# kotton-relay — reference

The Kotton relay performs two functions:

1. **Peer address exchange** — nodes announce their QUIC listen address; other nodes
   look up addresses by DID. The relay never sees file content or encryption keys.
2. **Blind circuits** — when two devices cannot reach each other directly, the relay
   bridges bytes between them. The circuit is mutually authenticated end to end; the relay
   forwards frames it cannot read.

The relay **carries and keeps nothing** (RFC-0083). There is no inbox: a message for a
device that is asleep goes to the user's own always-on node — the vault — never to this
process. Every route the relay answers is a per-contact, per-epoch handle, so an operator
learns that *a handle* was reachable at *some address* at *some time*, and two observations
do not compose into a record of anyone. **Anyone can run a relay**; if you don't trust an
operator, point your nodes at one you run.

**To set one up, read the guide, not this:** [Run a relay](../../docs/use/run-a-relay.md), and
[the index](../../docs/use/README.md) for everything before and after it. This file describes
the files beside it.

---

## The files here

| File | On the host | What it is |
| --- | --- | --- |
| [`kotton-relay.service`](kotton-relay.service) | `/etc/systemd/system/` | the unit: runs `/usr/local/bin/kotton-relay` as `kotton-relay`, never root, because it reads bytes a stranger wrote; systemd makes `/var/lib/kotton-relay` for that user, mode 0700 |
| [`relay.env`](relay.env) | `/etc/kotton/relay.env` | the settings below; placed once by `install.sh`, never overwritten, root's, mode 0600 |
| [`relay.example.toml`](relay.example.toml) | — | every tunable with its default and its CLI flag |
| [`Dockerfile`](Dockerfile), [`docker-compose.yml`](docker-compose.yml) | — | a relay in a container from a checkout; **not how a host runs it** |
| `Cargo.toml`, `src/` | — | its own workspace; `just relay::build` builds it without Docker |

`cargo xtask release-server relay` packs the unit and `relay.env` with a static binary,
`install.sh`, `REVISION` and `SHA256SUMS`. Edit `/etc/kotton/relay.env`, then
`systemctl restart kotton-relay`.

## Settings

All settings are environment variables — on the host, lines of `/etc/kotton/relay.env`; in a
container, `environment:` in `docker-compose.yml`.

| Variable | Default | Description |
|---|---|---|
| `KOTTON_RELAY_BIND` | `0.0.0.0:7700` | Listen address and port — the [port table](../README.md)'s 7700/tcp |
| `KOTTON_RELAY_TTL` | `60` | Peer-address entry TTL (seconds) |
| `KOTTON_RELAY_TLS_CERT` | _(unset)_ | PEM certificate path (enables TLS) |
| `KOTTON_RELAY_TLS_KEY` | _(unset)_ | PEM private key path (enables TLS) |
| `KOTTON_RELAY_NO_AUTH_LOOKUP` | `false` | Disable signed-lookup requirement |
| `KOTTON_RELAY_STATE_DIR` | _(unset)_ | The rule, the operators' keys and the relay's own key; `/var/lib/kotton-relay` on the host |
| `KOTTON_RELAY_ADVERTISE` | _(empty)_ | The address the relay announces about itself, signed into its answer at `GET /identity` and carried as the hint in its line; on the host `install.sh` writes `http://<the host's address>:<the port KOTTON_RELAY_BIND names>` here, from `KOTTON_PUBLIC_ADDR` or a yes to the address the ssh session arrived at, only while it is empty or absent; the installer reads `relay.env` only in the plain form — every line blank, a comment, or `KEY=value` (or `KEY="value"`, `KEY='value'`) at the start of a line in printable ASCII with no quote or backslash in the value — and refuses a file with any other line, a line ending in a backslash, a carriage return or a NUL |
| `KOTTON_RELAY_STUN_BIND` | `0.0.0.0:7700` | The STUN responder (UDP); `relay.env` binds it to loopback, since no host has published it |
| `RUST_LOG`, `NO_COLOR` | `info`, `1` in `relay.env` | The journal's level; plain text in it |

**Keep `relay.env` in its plain form.** Two things read this file — the installer, and systemd
when it starts the relay — and they agree because each reads one plain form: every line blank,
a comment (`#` or `;` first, after any blanks), or `KEY=value`, `KEY="value"` or `KEY='value'` at
the start of the line, with no space around `=` or after the value, printable ASCII only, no
quote or backslash inside the value, and no line, a comment included, ending in a backslash or
holding a carriage return or a NUL. A file with any other line is refused before anything is
placed, naming the line and the form to rewrite it in. The causes are systemd's parser's, and
[the vault's reference](../vault/README.md#settings) names each.

**TLS**, two ways. A reverse proxy in front (nginx, Caddy — which handles Let's Encrypt) is
simpler, and the relay listens on plain HTTP behind it. Or set `KOTTON_RELAY_TLS_CERT` and
`KOTTON_RELAY_TLS_KEY` to PEM paths — in a container, paths inside it, mounted as a volume.

## The verbs at the host

Its one rule, and the operators who may set it over the wire, are kept in the state
directory. The verbs are typed as root, or as the relay's own user, and either way they run
as the relay's user: root's verb runs itself again as the directory's owner, so root opens
nothing in a directory that user controls, and the file written, mode 0600, is that user's
and the running relay reads it at the next operator request. The one thing root's verb
touches there first is an `operators` an older release left root's, which it gives back to
the owner holding its lines. Typed as anyone else, a verb reads and writes nothing and says which
user to run as. The operator verbs do not make the directory; `create` does, as whoever types
it — the installer types it as the relay's own user.

```sh
kotton-relay --state-dir /var/lib/kotton-relay create --operator <key>
kotton-relay --state-dir /var/lib/kotton-relay operator enrol <key>
kotton-relay --state-dir /var/lib/kotton-relay operator revoke <key>
kotton-relay --state-dir /var/lib/kotton-relay operator revoke --all --keep <key>
```

**A relay is created for its operator's key, and does not start without one** (RFC-0084, the
amendment of 2026-10-01). `create`, run once before the relay serves — `install.sh` runs it when
given `KOTTON_OPERATOR_KEY` — makes the relay's own key (`identity.key`), writes the key it is
given as the first line of `operators`, and prints the relay's line as its last output:
`kotton-instance:relay:<its key>@<the address it announces>`. Every start prints that line again;
it confers nothing. Once bound, a start also prints where it listens, read off its sockets:
`listening http=<addr> stun=<addr>` — the one line meant to be read for the port when `--bind` asks for port 0 (the `info` log says it too, as a log).
Over a relay that has an operator, `create` refuses and changes nothing; over
state from before `create` existed that names none, it adopts it, keeping its key; it never makes
a key over existing state. A relay whose `operators` is empty, or missing, refuses to start and
names `create`; started with no state directory, it takes `--operator <key>` and keeps its rule,
its own key and that operator in memory for the life of the process, and without it refuses
too. `create` and a serving relay exclude each other: each takes an exclusive lock on
`instance.lock` in the state directory, and the second refuses rather than waits.

**The operator set is never empty.** `operator enrol` adds to a set that has an operator, and on
an empty one refuses, writes nothing and names `create`. `operator revoke <key>` refuses the last;
`--all --keep <key>` ends every operator but that one. The key is the one a desktop's `mint relay`
printed — the relay's own, never a vault's (DEC-0087) — and the desktop then says `enrol
<the relay's line>` and `relay rule [<r>] [<rule>]`, naming the relay only when it operates more than one. **Until its operator sets a rule the relay admits
nobody**: no reservation, no circuit, no address kept. `curl http://<host>:7700/health` answers
`{"address_entries":0,"status":"ok"}`; a node is pointed at a relay with
`kotton config relay set <url>`.

## Security notes

- The relay learns **which handle is announcing** and **from which IP address**, and nothing
  else. Handles are per-contact and per-epoch, so they name no one durably.
- Circuit frames are mTLS ciphertext between the two devices; the relay cannot read them.
- Peer-address lookups require a DID-signed `Authorization` header by default
  (`KOTTON_RELAY_NO_AUTH_LOOKUP=false`). This prevents enumeration of registered DIDs.
- TLS is strongly recommended on public relays. Without it, the peer-address lookup
  responses are visible to a network observer (though they contain only DIDs and addresses,
  not content).
- What it keeps is its own configuration: the rule, the operators' public keys, its own
  signing key (`identity.key`, mode `0600`, made at creation) and the lock file `create` and a
  serving relay take (`instance.lock`), in `KOTTON_RELAY_STATE_DIR`. Nothing it carries is kept.
- **The relay is its key, not its address.** `GET /identity?nonce=<hex>` answers the relay's
  public key and a signature over the caller's nonce and `KOTTON_RELAY_ADVERTISE`; a device
  records the key when it learns the relay, so a stand-in at the same address cannot answer
  as it. Losing `identity.key` makes the relay a stranger to every device that knows it — back
  it up with the state directory. If it is lost, each device that knows the relay forgets
  the old key in two steps, `kotton config relay clear` and then `kotton config relay set
  <url>`, which meets the relay anew; setting the same URL again without the clear keeps the
  old key and refuses the new one. A relay with no state directory keeps no key.

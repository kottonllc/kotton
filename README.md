# Kotton

Nine lines at a terminal on Linux: install, an identity, a folder kept, a second device, a host
of your own, and recovery. Each comment says what happens when you press Enter.

```sh
# Downloads the release archive, checks its signature against the key in the
# checkout, installs it under ~/.local/opt/kotton and links kotton and
# kotton-start into ~/.local/bin. No account.
git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton-dist && sh kotton-dist/install.sh

# Starts the daemon in this terminal.
# Leave it running (Ctrl-C stops it) and type the rest in another terminal.
kotton-start

# Makes a keypair on this machine and asks for a passphrase that unlocks it here.
# "alice" is only your label for the key.
kotton id create alice

# Copies the folder into your sealed tree as /Photos, hidden files too, and says
# how many went in. Run it again and it copies only what is new or changed.
kotton keep ~/Photos

# Prints a code and waits. On the other device, after installing: kotton id join alice <code>
# That device shows six digits; type them here. kotton sync on either then
# brings the other's things over.
kotton device add

# Makes a key for your relay and one for your vault, and prints two lines. Paste
# both on an always-on machine with a public address, as root; it prints one line back.
kotton mint host

# Tells this device where its relay and vault are, and asks "keep your things
# here too?". Answer y: your other devices now reach this one from anywhere, and
# the vault keeps a sealed copy it cannot read.
kotton enrol <the line the host printed>

# Prints twenty-four words and one line, once. Write both on paper.
kotton id add-recovery alice

# On a new machine: asks for your name, the words, the line and a passphrase
# for this machine, fetches your identity and your things from the vault, and
# this machine is yours again.
kotton id recover
```

`<tag>` is the release's tag on the [releases page](https://github.com/kottonllc/kotton-dist/releases).
Every command takes `--help`.

## The host's side

A host is one always-on machine that runs your own relay and your own vault together. The relay
introduces your devices to each other wherever each one is; the vault keeps your things sealed
for a device that wakes while every other one sleeps. Setting both up is three pastes:
`kotton mint host` at your desktop, the two lines it prints pasted at the host, and the one line
the host prints back, given to `kotton enrol`.

### The host

Any machine that is always on and has a public address. On a rented one:

- **Image:** Ubuntu 24.04 LTS. It has everything the install uses — `git`, `curl`,
  `ssh-keygen`, `sha256sum`, `tar`, `sh`, `systemd` — and both binaries are static, so nothing
  is installed first.
- **Size:** the cheapest. The host runs a release and never builds one.
- **Authentication:** an SSH key of its own, made on your machine and named, so no key you
  already have is overwritten:

  ```sh
  ssh-keygen -t ed25519 -f ~/.ssh/kotton_host -C "kotton host"
  ```
- **Ports:** **7700/tcp** for the relay and **7710/udp** for the vault. A stock image's `ufw`
  is inactive; a provider's own firewall needs both opened.

### 1. Mint the keys, on your desktop

```sh
kotton mint host
```

It makes two operator keys in your own store, one for the relay and one for the vault, and
prints the two lines the host runs, with the public half of each key in the second:

```text
git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton-dist
KOTTON_OPERATOR_KEY_RELAY=<relay key> KOTTON_OPERATOR_KEY_VAULT=<vault key> sh kotton-dist/install.sh --kind host
```

`<tag>` is a release's tag on the distribution's
[releases page](https://github.com/kottonllc/kotton-dist/releases), as in the first of the nine
lines: a desktop built here knows this repository's tags, not the distribution's, so it
prints `<tag>` and says where to find one. The keys are 64 hex characters each. The
secrets never leave your store. A relay and a vault are two instances under two keys even on
one machine, so one key never stands for both. With no `--rule` the relay admits *only my
devices*; `--rule people_i_invite` or `--rule anyone` gives it another first rule.
**Running a release you built yourself?** Mint with `kotton mint host --rev <rev>` instead;
`kotton mint host --key` prints the two keys alone, the relay's first, for a provider
that takes keys and not commands. A bare `kotton mint` lists the keys minted and not yet
enrolled.

### 2. Paste both lines at the host

As root, the two lines `mint host` printed, pasted whole and on their own, since the second asks
one question (below). The first clones the release at its tag; the second checks it and installs
it:

- **What the script checks.** It reads the release from the checkout, then checks the release's
  `SHA256SUMS.sig` against the distribution's
  [`infra/release/allowed_signers`](https://github.com/kottonllc/kotton-dist/blob/main/infra/release/allowed_signers)
  as the tag holds it, and the host's archive against the signed `SHA256SUMS`, before anything
  is unpacked: **a
  release with no `SHA256SUMS.sig` has not been signed, and nothing from it runs**.
- **What it installs.** The host's archive holds the relay's archive and the vault's, whole,
  and its `install.sh` runs each one's own installer in turn: each makes its own user,
  `kotton-relay` and `kotton-vault`, with no home, no shell and no password; places its binary
  in `/usr/local/bin`, its unit in `/etc/systemd/system` and its settings in `/etc/kotton` —
  `relay.env` and `vault.env`, written the first time only and yours to edit; and creates its
  instance for its own key, as its own user, never as root. Then it starts both under
  systemd, now and at every boot.
- **Which it installs.** Both, unless the install line says otherwise:
  `KOTTON_HOST_KINDS=relay` in front of it installs the relay alone, and
  `KOTTON_HOST_KINDS=vault` the vault alone, each given its own key and no other
  (`KOTTON_OPERATOR_KEY_RELAY` or `KOTTON_OPERATOR_KEY_VAULT`). It never asks which: a host is
  both unless you say so.
- **Its one question** is the host's address. It proposes the one your ssh session arrived at,
  and on `y` writes it for both: the relay's `KOTTON_RELAY_ADVERTISE=http://<ip>:7700` and the
  vault's `KOTTON_PUBLIC_ADDR=<ip>`. The vault is not asked again.

Its last output is the host's line, one row naming both instances:

```text
kotton-instance:relay:<the relay's key>@http://<ip>:7700 kotton-instance:vault:<the vault's key>@<ip>:7710
```

The line confers nothing: it says where each instance is and which key to expect there.

**Behind NAT or on a floating IP**, devices dial an address the ssh session did not arrive at.
Give that one in front of the second line —
`KOTTON_PUBLIC_ADDR=<ip> KOTTON_OPERATOR_KEY_RELAY=<relay key> KOTTON_OPERATOR_KEY_VAULT=<vault key> sh kotton-dist/install.sh --kind host`
— and it asks nothing. With no terminal to ask at, it writes no address, says so, and prints the
command that writes it, `KOTTON_PUBLIC_ADDR=<ip> sh kotton-dist/install.sh --kind host`, run from
the same directory. That fills the empty address in both settings and restarts both, and each
instance prints its line again at that start, to the journal:

```sh
journalctl -u kotton-relay -o cat --no-pager | grep kotton-instance:relay | tail -1
journalctl -u kotton-vault -o cat --no-pager | grep kotton-instance:vault | tail -1
```

Give both lines to your desktop together, as the host's line would have.

### 3. Give the line to your desktop

```sh
kotton enrol <the line the host printed>
```

Your desktop reads the row as the relay's line and the vault's. It dials each at the address
its line names and holds it to the key its line names, then asks it, as its operator, under the
key you minted for it: an instance proving another key, or refusing that one, is refused and
nothing of it is kept. Then it keeps both credentials sealed in your store, sets the relay's
first rule, and tells the vault to stand at the relay. It ends on one question:

```text
keep your things here too? [y/N]
```

`y` makes this desktop a tenant of your own vault and runs the first sync; and a desktop that
stands at no relay yet then stands at yours, held to its key, so your other devices reach it
away from its own network. Anything else changes nothing, and `kotton vault invite --me` takes
the offer later.

From your PC, `curl http://<ip>:7700/health` answers `{"address_entries":0,"status":"ok"}`:
the relay's port is reachable, not merely bound.

## What this is

This repository is Kotton's system: `kuserd`, the daemon that holds your identity, your keys
and your sealed tree; `kdeviced`, the device daemon that starts one `kuserd` for each person on
the machine; `kquicd`, which accepts your other devices' connections, and `ksyncd`, which tells
the daemon when your tree has changed; the `kotton` command line; the vault, `kvaultd`, and the
relay, `infra/relay`; and `kotton-start`. It builds from this tree alone, with the toolchain
`rust-toolchain.toml` names, and each of its `v*` tags attaches the archives built from that
commit to its own release. A person installs from the distribution,
[kottonllc/kotton-dist](https://github.com/kottonllc/kotton-dist): its release lock names which
of those archives go together, its `install.sh` is the one the first line runs, and that script
unpacks nothing until the release's signature checks against the key the distribution's tag
holds. Your things are yours because only you hold the keys they are sealed under: you can put
them on any host, and grant them to whom you choose.

## Pre-alpha

Kotton is **pre-alpha**. Put nothing in it you cannot afford to lose. A release is a signed tag
of the distribution; until the first one exists, the first line has nothing to download.

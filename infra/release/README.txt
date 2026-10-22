Kotton — a build for a friend
=============================

Pre-alpha. Put nothing in it you cannot afford to lose.

This archive is everything Kotton needs to run: the daemons, the sandbox that
runs apps, the window, the command line, and the shell the window draws. It
needs no Rust, no Python and no development packages. It holds no key, no
account and nothing that reports anywhere; installing it copies files.

Install
-------

    sh install.sh

That puts Kotton in ~/.local/opt/kotton and links `kotton` and `kotton-start`
into ~/.local/bin. Run it again from a newer archive to upgrade.

Start
-----

    kotton-start

Then, from another terminal, `kotton id create <name>` makes your identity and
`kotton` enters Kotton's shell as it; on a machine with a GPU the window opens
and asks the same. Nobody issues the identity and no server is told.

From another terminal, `kotton --help` is everything else. Every command takes
--help, and that is the authority on its arguments.

What this machine needs
-----------------------

Linux on x86_64 with glibc 2.39 or newer: Ubuntu 24.04, Fedora 40, Debian 13
and later. Older ones (Ubuntu 22.04, Debian 12) will not run it.

The runtime libraries a desktop usually already has — on Ubuntu 24.04 the
packages libgtk-3-0t64, libxdo3, libayatana-appindicator3-1 and libssl3t64.
No development packages.

A GPU the window can render on. Without one Kotton runs without a window, says
so, and the command line still works.

REVISION says which commit this was built from and what it was built for.
THIRD-PARTY-NOTICES names every library it is built from, its version and its
license, with the license texts. LICENSE and NOTICES are Kotton's own: the
terms it is given to you under, which travel with it if you pass it on.
install.sh keeps all three beside the binaries.

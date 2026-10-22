set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Releases: what a person installs, built once where a toolchain is.
#
#   just release::desktop build the desktop --release for this machine's platform, pack it as one archive under out/dist/, and install-test that archive
#
# The relay and the vault are released by `cargo xtask release-server relay|vault`,
# which has no recipe here: it is Rust, so there is no shell for a platform to pick
# wrongly, and it needs neither Docker nor a registry (docs/use/build-a-release.md).
# `box`, which built and pushed images to ghcr.io, went with that ruling.

# **The build a friend installs**: the daemons, the runner, the window, the CLI and the shell as one
# archive, `out/dist/kotton-<sha>-<os>-<arch>.tar.gz`, that needs no Rust, no Python and no
# development headers where it is unpacked.
#
# One recipe for every platform, because it is `cargo xtask release` and that is Rust:
# it names the archive for the machine it runs on, so each platform's archive is made on
# a machine of that platform. There is no CI to make them anywhere else.
#
# **It tests what it made before it names it.** The last step installs the archive into a
# clean directory, starts it from there and runs `kotton id create` at a terminal from the
# installed prefix (`cargo xtask release-test`); an archive that fails prints no name and
# the recipe exits non-zero. The layout, and why the installed daemon finds everything
# beside itself, are in `xtask/src/release.rs`.
#
# Refuses a tree with uncommitted changes, as `release-server` does: the archive's name is a
# claim about what it holds. `--allow-dirty` makes one named `-dirty`, which is not a release.
#
#   just release::desktop
#   just release::desktop --allow-dirty
#   just release::desktop --no-build          pack what out/target/release already holds
#
# Build the desktop --release, pack it as one archive under out/dist/, and install-test it
desktop *args:
    cargo xtask release {{args}}

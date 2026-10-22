set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Code-generation recipes — invoked as `just gen::docs`, `just gen::docs_check`.

# Regenerate docs/cli/reference.md and docs/shell/reference.md.
docs:
    cargo xtask-docs gen-docs

# Check the generated docs match the command tree. Delegates to the xtask check,
# which `just lint` also runs.
#
# This used to be `gen-docs` followed by `git diff --exit-code docs/`, which
# *repaired* the tree before checking it: on a dirty working copy it went green
# while hiding the drift, and it could not tell a real change from the LF/CRLF
# rewrite `core.autocrlf` produces on Windows. The xtask version compares in
# memory and never writes.
docs_check:
    cargo xtask-docs docs-check

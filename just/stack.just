set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Stacks: real topologies of real images (infra/scenarios), for the conductor
# to prove and for a person to poke at — locally, or on a machine you have ssh to.
#
#   just stack::run lan            the conductor runs the scenario; exit code is the verdict
#   just stack::up relay           stand the topology up and leave it running
#   just stack::logs relay         follow everything
#   just stack::shell relay laptop a shell inside a node (`kotton` is the CLI there)
#   just stack::down relay         stop it and drop its volumes
#
# Remote: any recipe, with DOCKER_HOST pointing at a machine you can ssh to.
#   DOCKER_HOST=ssh://me@vps just stack::up rental
# The images build on that machine from this checkout (the build context is
# sent over ssh; .dockerignore keeps it small). `just stack::remote` wraps that.
#
# Scenarios: lan, relay, rental — see infra/scenarios/README.md.

compose := "docker compose"

# Run a scenario end to end: build, start, conduct, report, stop. The
# conductor's exit code is the result.
#
# From nothing, every time. `up` alone reuses the volumes a previous run left,
# so the second `just stack::run` on a machine failed at its first step with
# `User 'alice' already exists` (2026-09-14, the first machine to run rental
# twice). A scenario that can only be run once is not a scenario anyone re-runs.
run scenario:
    {{compose}} -f infra/scenarios/{{scenario}}.yml --profile auto down -v --remove-orphans
    {{compose}} -f infra/scenarios/{{scenario}}.yml --profile auto up --build --abort-on-container-exit --exit-code-from conductor

# Stand a scenario up without the conductor and leave it running.
up scenario:
    {{compose}} -f infra/scenarios/{{scenario}}.yml up -d --build

# Run only the conductor against a stack that is already up.
conduct scenario:
    {{compose}} -f infra/scenarios/{{scenario}}.yml --profile auto run --rm conductor {{scenario}}

# Stop a scenario and drop what it kept.
down scenario:
    {{compose}} -f infra/scenarios/{{scenario}}.yml --profile auto down -v

# Follow the logs of every service, or one.
logs scenario service="":
    {{compose}} -f infra/scenarios/{{scenario}}.yml logs -f {{service}}

# A shell inside one service.
shell scenario service:
    {{compose}} -f infra/scenarios/{{scenario}}.yml exec -it {{service}} sh

# What is running.
ps scenario:
    {{compose}} -f infra/scenarios/{{scenario}}.yml ps

# Any of the above on a remote machine: `just stack::remote me@vps up rental`.
remote host recipe scenario:
    DOCKER_HOST=ssh://{{host}} just stack::{{recipe}} {{scenario}}

# Hand the images binaries built here instead of compiling inside docker:
# fills infra/prebuilt/ from a host release build, for `ARTIFACTS=prebuilt`.
# Behind a mirror or a proxy this is how the images get built at all — see
# the argument list at the top of infra/Dockerfile.
prebuilt:
    cargo build --release --bin kuserd --bin khttpd --bin kvaultd --bin kotton --bin kscenario
    cargo run --release -p xtask -- build-web
    rm -rf infra/prebuilt/web && mkdir -p infra/prebuilt
    # Where cargo put them, asked rather than composed (`cargo xtask out`).
    t="$(cargo xtask out target)/release" && cp "$t/kuserd" "$t/khttpd" "$t/kvaultd" "$t/kotton" "$t/kscenario" infra/prebuilt/
    cp "$(cargo xtask build-relay --release)" infra/prebuilt/
    cp -r client/web infra/prebuilt/web

# Build every image once, without running anything.
build:
    docker build -f infra/Dockerfile --target node -t kotton-node .
    docker build -f infra/Dockerfile --target vault -t kotton-vault .
    docker build -f infra/Dockerfile --target gateway -t kotton-gateway .
    docker build -f infra/Dockerfile --target conductor -t kotton-conductor .
    docker build -f infra/Dockerfile --target router -t kotton-router .
    docker build -f infra/relay/Dockerfile -t kotton-relay .

set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# User management recipes — invoked as `just user::create`, `just user::auth`, etc.

# Create a new identity. Prompts for a name if omitted: `just user::create`.
create name="":
    cargo run --bin kotton -- id create {{name}}

# List all users on this device.
list:
    cargo run --bin kotton -- id list

# Remove a user by name.
rm name:
    cargo run --bin kotton -- id rm {{name}}

# Authenticate a user and cache a session token.
# Run after `just user::create <name>` and after any daemon restart.
auth user:
    cargo run --bin kotton -- login {{user}}

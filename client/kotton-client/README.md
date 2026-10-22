# kotton-client

**Client SDK**

`KottonClient` — the typed async IPC client for talking to a running `kuserd` daemon. The CLI, the shell REPL, and the Tauri host all communicate through this crate.

## Usage

```rust
use kotton_client::KottonClient;

let client = KottonClient::connect().await?;
client.set_session_token(token);
let files = client.list_files("/").await?;
```

## Key public type

`KottonClient` — a typed async IPC client. Constructed by `connect()` (auto-discovers
the local daemon socket) or `connect_to(path)` (explicit socket path). Every method
is a single `async` round-trip: one `DeviceRequest` sent, one `DeviceResponse` back.

## Method domains

| Module       | Methods                                                                                             |
| ------------ | --------------------------------------------------------------------------------------------------- |
| `connect`    | `connect`, `connect_to`, `set_session_token`                                                        |
| `session`    | `create_user`, `login_with_recovery_key`, `unlock_with_pin`, `lock`, `logout`, `authenticate`       |
| `filesystem` | `list_files`, `read_file`, `write_file`, `delete_file`, `create_dir`, `copy`, `move_file`, `rename` |
| `records`    | `create_record`, `get_record`, `update_record`, `delete_record`, `list_records`, `query_records`    |
| `apps`       | `install_app`, `launch_app`, `list_installed`, `uninstall_app`                                      |
| `network`    | `sync_now`, `list_remote_backends`, `add_remote_backend`, `remove_remote_backend`                   |
| `crypto`     | `get_key_health`, `migrate_to_algorithm`                                                            |
| `schema`     | `register_schema`, `get_schema`, `list_schemas`                                                     |
| `events`     | `subscribe_events`, `verify_event_log`                                                              |

## Re-exported types

Callers do not need to add `kotton-protocol` as a direct dependency. The following
types are re-exported from `kotton` directly:
`DeviceRequest`, `DeviceResponse`, `RemoteBackend`, `RemoteConfig`, `SyncResult`,
`PairedNode`, `EphemeralSession`, `KeyHealth`, `EventEntry`, and more.

## Does not

Contain any daemon logic. This is a pure IPC client — it holds no state beyond
the connection handle and an optional session token.

## Depends on

`kotton-platform`, `kotton-protocol`, `kotton-providers-ipc`, `kotton-static`.

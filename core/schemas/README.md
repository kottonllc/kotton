# kotton-schemas

User record schema definitions for the Kotton data layer (v0.4+).

This crate is distinct from `kotton-protocol` (IPC wire types). It provides the vocabulary for structured user data.

## Modules

| Module       | Contents                                                                                        |
| ------------ | ----------------------------------------------------------------------------------------------- |
| `nsid`       | `Nsid` — validated reverse-domain schema identifiers                                            |
| `field`      | `FieldType`, `SchemaField` — column type declarations                                           |
| `definition` | `SchemaDefinition` — versioned field list for a record table                                    |
| `capability` | `CapabilityGrant`, `CapabilitySet` — minimum-surface access declarations and runtime checking   |
| `core`       | `CoreSchema` — the five standard schemas (`notes`, `contacts`, `calendar`, `messages`, `tasks`) |

## Core schemas

```
sh.kotton.notes      — title, body, tags, created_at, updated_at
sh.kotton.contacts   — display_name, dids, emails, phones
sh.kotton.calendar   — title, start_at, end_at, participants, location?
sh.kotton.messages   — sender_did, body, thread_id, sent_at
sh.kotton.tasks      — title, due_at?, completed, parent_task_id?
```

Core schemas are sealed — apps extend via `SchemaDefinition::extends`, not by modifying core definitions.

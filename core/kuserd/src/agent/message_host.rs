// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's implementation of [`MessageHost`].
//!
//! The messaging domain asks for six things (see the trait's own note): a
//! keychain, a user directory both ways, the user's current key, a contact's
//! stored key, and per-user record access. **No single object in the daemon has
//! all six** — the machine holds four, and which users are resident is the
//! daemon's own bookkeeping — so the daemon composes them here.
//!
//! That composition is the point rather than an inconvenience. `messages.rs`
//! used to take `&DeviceRuntime` *and* `&UserRegistry` and do the joining
//! itself, which is how a domain ends up naming both the machine and the
//! daemon's internals. Now the joining happens once, on the side that owns both
//! halves, and the domain names neither.
//!
//! This type stays in `kuserd` when `messages.rs` becomes `core/msg`: the trait
//! travels with the domain, the implementation stays with whoever can satisfy
//! it.
use crate::residency::UserRegistry;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use crate::agent::outbox_shelf::Outbox as _;
use kotton_msg::daemon::messages::{judge_reach_note, MessageHost};
use kotton_msg::daemon::outbox::{OutboxEntry, Retry, SignedFor};
use kotton_peer::membership::Membership;
use kotton_sys::secret::SecretsStore;
use serde_json::Value;

/// The machine and the daemon's residency map, presented as one host.
pub struct DaemonMessageHost<'a> {
    pub runtime: &'a DeviceRuntime,
    pub users: &'a UserRegistry,
    /// Which record stores are open. The record verbs below need a store, and
    /// which one is open is the daemon's bookkeeping rather than the machine's.
    pub record_stores: &'a crate::residency::RecordStores,
}

#[async_trait::async_trait]
impl MessageHost for DaemonMessageHost<'_> {
    fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
        self.runtime.secrets()
    }

    fn user_aid(&self, user_id: &str) -> Option<String> {
        self.runtime.user_aid(user_id)
    }

    fn local_user_for_did(&self, did: &str) -> Option<String> {
        self.runtime.local_user_for_did(did)
    }

    fn user_current_key(&self, user_id: &str) -> Option<[u8; 32]> {
        self.runtime.user_current_key(user_id)
    }

    /// Every relay a contact is reached at: each one their reach note lists,
    /// in the order they prefer, and then this node's own — each once
    /// ([`contact_relays`]). This node's own relay is where two people who met
    /// through one relay reach each other, and where a contact whose note has
    /// not arrived, or has expired, can still be found; it is dialled beside
    /// the note's relays rather than only instead of them.
    ///
    /// Nothing durable goes to any of them: every dial is labelled by the
    /// pair's per-epoch handles (`kotton_peer::contact_delivery`),
    /// the same labels at every relay, and the list comes only from the sealed
    /// note and this node's own settings.
    ///
    /// A co-member — somebody this person shares a channel with and holds no
    /// card for — is dialled the same way from what the channel's roster
    /// carries for them ([`Self::far_end`]).
    async fn contact_paths(
        &self,
        user_id: &str,
        contact_did: &str,
    ) -> Result<Vec<kotton_msg::daemon::outbox::Path>, String> {
        let far = self.far_end(user_id, contact_did).await?;
        Ok(contact_paths_from(
            contact_relays(
                far.reach.as_ref(),
                &self.runtime.reachability().nat().relay_url,
                kotton_peer::rendezvous::unix_now(),
            ),
            self.runtime.local_way_here(),
        ))
    }

    /// Say `request` — the recipient's copy, handed over or carried — at their
    /// door along one path, at a relay or on the local network by
    /// the way this device's open door handed out, and return what the door
    /// answered.
    async fn deliver_on(
        &self,
        user_id: &str,
        contact_did: &str,
        path: &kotton_msg::daemon::outbox::Path,
        request: &kotton_wire::ipc::ContactRequest,
    ) -> Result<kotton_wire::ipc::ContactResponse, String> {
        let way = path
            .way::<Way>()
            .ok_or_else(|| "not a path this node made".to_owned())?;
        // The *sender* is owed four words, and the domain composes the
        // one they read from every path's answer. The person running **this**
        // node is owed which relay did what, and it is said here, per path:
        // a path that always fails the same way cannot otherwise be told from
        // a path that is broken.
        let failed = |reason: String| {
            tracing::info!(
                user_id,
                contact = %contact_did,
                path = %way,
                reason = %reason,
                "a contact's door did not answer at this relay"
            );
            reason
        };
        let member = self.far_end(user_id, contact_did).await.map_err(&failed)?;
        let key = kotton_peer::daemon::nodes::load_signing_key(user_id, self.secrets())
            .map_err(|e| failed(format!("this identity's key is not available: {e}")))?;
        let first = self.dial_door(user_id, way, &key, &member, request).await;
        if first.is_ok() {
            return first.map_err(&failed);
        }
        // A contact who has not yet learned this person's rotation still answers
        // at the door the pair derived from the key it holds — the key the
        // rotation retired. So that door is dialled too, derived from each key
        // this node kept, and it is how the note carrying the key log reaches
        // them at all: a rotated person's contacts keep the key it retired.
        //
        // A door's keys route and prove nothing about a person — a vault is
        // handed them — so this gives a retired key no authority:
        // what arrives is signed with the current key, and believed only under
        // the key the sender's own log proves.
        //
        // It is not bounded by the contact having learned the key: this node
        // cannot tell a contact who has not learned it from one who is offline,
        // so every hand-over whose current door does not answer also dials the
        // door of every retired key kept, each under its own timeout, for as
        // long as those keys are kept. Nothing bounds it yet.
        for retired in self.retired_identity_keys(user_id, &key) {
            if let Ok(answer) = self.dial_door(user_id, way, &retired, &member, request).await {
                return Ok(answer);
            }
        }
        first.map_err(&failed)
    }

    /// Signed with this device's key, which the messaging domain never holds —
    /// it is handed an acknowledgement, and nothing else can be signed here.
    fn sign_delivery_ack(
        &self,
        message_id: &str,
        from_did: &str,
        to_did: &str,
    ) -> kotton_wire::ipc::DeliveryAck {
        kotton_crypto::delivery_ack::sign(message_id, from_did, to_did, self.runtime.device_signing_key())
    }

    async fn contact_reach_note(
        &self,
        user_id: &str,
        contact_did: &str,
    ) -> Option<kotton_crypto::reach_note::ReachNote> {
        self.users
            .get(user_id)?
            .read_member(contact_did)
            .await
            .ok()
            .flatten()
            .filter(|m| matches!(m.role, kotton_schemas::membership::Role::Contact))?
            .reach
    }

    /// The note this person's own store holds for them — read, not signed:
    /// the reach keeper signs and renews it.
    async fn own_reach_note(&self, user_id: &str) -> Option<kotton_crypto::reach_note::ReachNote> {
        self.users.get(user_id)?.read_own_reach_note().await.ok().flatten()
    }

    /// The doors are rebuilt as they are when a card changes: the mailbox
    /// opens a door for each co-member and the vault is handed theirs.
    fn rosters_changed(&self, _user_id: &str) {
        self.runtime.contacts_changed().notify_one();
    }

    async fn outbox_entries(&self, user_id: &str) -> anyhow::Result<Vec<OutboxEntry>> {
        self.store(user_id)?.outbox_entries().await
    }

    async fn keep_outbox_entry(&self, user_id: &str, entry: &OutboxEntry) -> anyhow::Result<()> {
        self.store(user_id)?.keep_outbox_entry(entry).await
    }

    async fn drop_outbox_entry(&self, user_id: &str, id: &str) -> anyhow::Result<()> {
        self.store(user_id)?.drop_outbox_entry(id).await
    }

    async fn keep_signed_for(&self, user_id: &str, signed: &SignedFor) -> anyhow::Result<()> {
        self.store(user_id)?.keep_signed_for(signed).await
    }

    async fn all_signed_for(&self, user_id: &str) -> anyhow::Result<Vec<SignedFor>> {
        self.store(user_id)?.all_signed_for().await
    }

    fn outbox_retry(&self) -> Retry {
        outbox_retry()
    }

    async fn keep_reach_note(
        &self,
        user_id: &str,
        contact_did: &str,
        note: kotton_crypto::reach_note::ReachNote,
    ) -> Result<kotton_crypto::reach_note::Kept, kotton_msg::daemon::messages::NotKept> {
        use kotton_crypto::reach_note::Kept;
        use kotton_msg::daemon::messages::NotKept;
        let store = self
            .users
            .get(user_id)
            .ok_or_else(|| NotKept::Failed(format!("'{user_id}' is not available on this node")))?;
        let member = store
            .read_member(contact_did)
            .await
            .map_err(|e| NotKept::Failed(format!("could not read the card for {contact_did}: {e}")))?;
        let kept = judge_on_card(member.as_ref(), &note, contact_did, kotton_peer::rendezvous::unix_now())?;
        if let Some(mut member) = member.filter(|_| kept == Kept::Replaced) {
            member.reach = Some(note);
            store
                .write_member(&member)
                .await
                .map_err(|e| NotKept::Failed(format!("could not keep the reach note: {e}")))?;
            tracing::debug!(user_id, contact = %contact_did, "a contact's reach note was replaced");
        }
        Ok(kept)
    }

    fn own_key_log(&self, user_id: &str) -> Vec<kotton_wire::kel::KelEvent> {
        kotton_identity::kel_store::load_chain(self.runtime.base_dir(), user_id).unwrap_or_else(|e| {
            tracing::warn!(user_id, "own key log unreadable, so none travels with the reach note: {e}");
            Vec::new()
        })
    }

    fn contact_key_log(&self, user_id: &str, contact_did: &str) -> Vec<kotton_wire::kel::KelEvent> {
        kotton_identity::kel_store::load_contact_chain(self.runtime.base_dir(), user_id, contact_did)
            .unwrap_or_else(|e| {
                tracing::warn!(user_id, contact = %contact_did, "a contact's kept key log is unreadable: {e}");
                Vec::new()
            })
    }

    /// The log first, then the card: a card written and a log not would leave
    /// the next log that arrives checked against the older one, which it still
    /// continues — so either order recovers, and this one never holds a key the
    /// kept log cannot account for. The mailbox is rebuilt, because the pair's
    /// door is derived from the contact's key. The device allowlist is not
    /// touched: a contact is not on it (`admit` in `kotton_device::users::contacts`),
    /// and a learned key
    /// puts them there no more than pairing does.
    async fn adopt_contact_key(
        &self,
        user_id: &str,
        contact_did: &str,
        log: &[kotton_wire::kel::KelEvent],
        key: [u8; 32],
    ) -> Result<(), kotton_msg::daemon::messages::NotKept> {
        use kotton_msg::daemon::messages::NotKept;
        let store = self
            .users
            .get(user_id)
            .ok_or_else(|| NotKept::Failed(format!("'{user_id}' is not available on this node")))?;
        let mut member = store
            .read_member(contact_did)
            .await
            .map_err(|e| NotKept::Failed(format!("could not read the card for {contact_did}: {e}")))?
            .filter(|m| matches!(m.role, kotton_schemas::membership::Role::Contact))
            .ok_or_else(|| NotKept::Refused(format!("{contact_did} is not a contact")))?;
        kotton_identity::kel_store::save_contact_chain(self.runtime.base_dir(), user_id, contact_did, log)
            .map_err(|e| NotKept::Failed(format!("could not keep {contact_did}'s key log: {e}")))?;
        if member.public_key == key {
            return Ok(());
        }
        member.public_key = key;
        store
            .write_member(&member)
            .await
            .map_err(|e| NotKept::Failed(format!("could not keep {contact_did}'s new key: {e}")))?;
        self.runtime.contacts_changed().notify_one();
        Ok(())
    }

    /// Absent when the user is not resident, which reads the same to the domain
    /// as "no key known for that DID" — and is the same answer either way: the
    /// message cannot be encrypted, and the caller says so by name.
    async fn member_public_key(&self, user_id: &str, did: &str) -> Option<[u8; 32]> {
        self.users.get(user_id)?.member_public_key(did).await
    }

    fn retired_identity_keys(
        &self,
        user_id: &str,
        current: &ed25519_dalek::SigningKey,
    ) -> Vec<ed25519_dalek::SigningKey> {
        kotton_identity::retired_keys::open(self.runtime.base_dir(), user_id, current)
            .unwrap_or_else(|e| {
                tracing::warn!(user_id = %user_id, "retired identity keys unreadable: {e}");
                Vec::new()
            })
    }

    /// The label on this person's membership record for the contact — the
    /// name the pair chose at the ceremony, which is what People shows.
    async fn contact_name(&self, user_id: &str, contact_did: &str) -> Option<String> {
        self.contact(user_id, contact_did).await.ok().and_then(|m| m.label)
    }

    /// The person's own tree — the root first run laid over their files,
    /// *Personal* (or *This PC*) — through the store's own listing, the one a
    /// Files window is answered from. A folder that is not there yet holds
    /// nothing, and is not an error.
    async fn personal_names(&self, user_id: &str, dir: &str) -> Result<Vec<String>, String> {
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        match store.path_kind(dir).await.map_err(|e| e.to_string())? {
            None => Ok(Vec::new()),
            Some(_) => Ok(store
                .list_children(dir)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|c| c.name)
                .collect()),
        }
    }

    /// `UserStore::write_file`: the write a person's own save makes, into the
    /// same tree, so the copy is sealed, logged and replicated as theirs is.
    async fn personal_write(&self, user_id: &str, path: &str, bytes: &[u8]) -> Result<(), String> {
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        store.write_file(path, bytes).await.map_err(|e| e.to_string())
    }

    /// A daemon object under `/network/streams/`, beside the outbox, in the
    /// person's own store: out of every app's reach and out of their tree
    /// (`MemberStore` writes no person path), and carried to their other
    /// devices by the same sync, as the outbox is.
    async fn stream_keep(&self, user_id: &str, key: &str, bytes: &[u8]) -> Result<(), String> {
        use kotton_peer::membership::MemberStore as _;
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        store
            .member_write(&format!("{STREAMS_PREFIX}{key}"), bytes)
            .await
            .map_err(|e| format!("could not keep part of a share: {e}"))
    }

    async fn stream_keys(&self, user_id: &str) -> Result<Vec<String>, String> {
        use kotton_peer::membership::MemberStore as _;
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        // Listed as the outbox is (`outbox_shelf`): a listing that cannot be
        // taken is an error — this node may be locked — never an empty shelf.
        let keys = store
            .member_list(STREAMS_PREFIX)
            .await
            .map_err(|e| format!("could not list the shares still arriving: {e}"))?;
        Ok(keys
            .into_iter()
            .filter(|k| !k.ends_with('/'))
            .filter_map(|k| k.rsplit('/').next().map(str::to_owned))
            .collect())
    }

    async fn stream_read(&self, user_id: &str, key: &str) -> Result<Vec<u8>, String> {
        use kotton_peer::membership::MemberStore as _;
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        store
            .member_read(&format!("{STREAMS_PREFIX}{key}"))
            .await
            .map_err(|e| format!("could not read part of a share: {e}"))
    }

    async fn stream_drop(&self, user_id: &str, key: &str) -> Result<(), String> {
        use kotton_peer::membership::MemberStore as _;
        let store = self.store(user_id).map_err(|e| e.to_string())?;
        store
            .member_delete(&format!("{STREAMS_PREFIX}{key}"))
            .await
            .map_err(|e| format!("could not let go of part of a share: {e}"))
    }

    async fn record_insert(
        &self,
        user_id: &str,
        nsid: &str,
        record: Value,
    ) -> anyhow::Result<String> {
        let store = self.record_stores.get_or_open(
            self.runtime.base_dir(),
            user_id,
            self.runtime.secrets(),
        )?;
        kotton_record::record_cmds::Record::new(&self.runtime.schema_registry, &store)
            .insert(nsid, record)
            .await
    }

    async fn record_query(
        &self,
        user_id: &str,
        nsid: &str,
        field_eq: Vec<(String, Value)>,
        limit: Option<usize>,
        offset: Option<usize>,
        before_id: Option<String>,
    ) -> anyhow::Result<Vec<Value>> {
        let store = self.record_stores.get_or_open(
            self.runtime.base_dir(),
            user_id,
            self.runtime.secrets(),
        )?;
        kotton_record::record_cmds::Record::new(&self.runtime.schema_registry, &store)
            .query(nsid, field_eq, limit, offset, before_id)
            .await
    }

    async fn record_delete(&self, user_id: &str, nsid: &str, record_id: &str) -> anyhow::Result<()> {
        let store = self.record_stores.get_or_open(
            self.runtime.base_dir(),
            user_id,
            self.runtime.secrets(),
        )?;
        kotton_record::record_cmds::Record::new(&self.runtime.schema_registry, &store)
            .delete(nsid, record_id)
            .await
    }
}

impl DaemonMessageHost<'_> {
    /// Dial `member`'s door along `way`, as the pair derives it from `key`.
    async fn dial_door(
        &self,
        user_id: &str,
        way: &Way,
        key: &ed25519_dalek::SigningKey,
        member: &FarEnd,
        request: &kotton_wire::ipc::ContactRequest,
    ) -> Result<kotton_wire::ipc::ContactResponse, String> {
        let relay = match way {
            Way::Relay(relay) => relay,
            Way::LocalNetwork(here) => return deliver_here(here, key, &member.public_key, request).await,
        };
        // The key to present at this relay. At this device's own relay by its
        // own record, this person's own key there, and the note's key only when
        // they hold none; at any other relay, the key the contact's note hands
        // for it (they run it, and invited this person) and nothing of this
        // person's — never chosen by the relay key the contact wrote beside the
        // address (`Reachability::present_at_supplied`).
        let handed = member
            .reach
            .as_ref()
            .and_then(|note| note.admit_at(relay, kotton_peer::rendezvous::unix_now()))
            .and_then(kotton_net::rendezvous::AdmissionKey::parse);
        let admission = self.runtime.reachability().present_at_supplied(user_id, relay, handed);
        match tokio::time::timeout(
            PATH_TIMEOUT,
            kotton_peer::contact_delivery::deliver(relay, key, &member.public_key, request, admission),
        )
        .await
        {
            Ok(answer) => answer.map_err(|e| format!("{e}")),
            Err(_) => Err(format!("no answer within {}s", PATH_TIMEOUT.as_secs())),
        }
    }

    /// `contact_did`'s card in `user_id`'s membership, or why a message cannot
    /// be handed to them.
    async fn contact(
        &self,
        user_id: &str,
        contact_did: &str,
    ) -> Result<kotton_schemas::membership::Member, String> {
        let store = self
            .users
            .get(user_id)
            .ok_or_else(|| format!("'{user_id}' is not available on this node"))?;
        match store.read_member(contact_did).await {
            Ok(Some(m)) => Ok(m),
            _ => Err(format!(
                "{contact_did} is not a contact — pair with them first, so their key and \
                 where to reach them are known rather than asserted"
            )),
        }
    }

    /// Who a hand-over to `did` reaches: their card's key and note, or — for
    /// somebody this person holds no card for and shares a channel with — the
    /// key and note that channel's roster carries for them
    /// (`kotton_msg::daemon::messages::co_member`). A card wins. Only where a
    /// copy is dialled is decided here; what a co-member may say at this
    /// person's door is the domain's (`delivery::co_member_may_say`).
    async fn far_end(&self, user_id: &str, did: &str) -> Result<FarEnd, String> {
        match self.contact(user_id, did).await {
            Ok(card) => Ok(FarEnd { public_key: card.public_key, reach: card.reach }),
            Err(no_card) => match kotton_msg::daemon::messages::co_member(self, user_id, did).await {
                Some(co) => Ok(FarEnd { public_key: co.key, reach: co.reach }),
                None => Err(no_card),
            },
        }
    }

    /// A resident person's store, or why not.
    fn store(&self, user_id: &str) -> anyhow::Result<std::sync::Arc<kotton_store::runtime::user::UserStore>> {
        self.users
            .get(user_id)
            .ok_or_else(|| anyhow::anyhow!("'{user_id}' is not available on this node"))
    }
}

/// The far end of a hand-over, as [`DaemonMessageHost::far_end`] finds it: the
/// identity key the pair's door is derived from, and the reach note it is
/// dialled by.
struct FarEnd {
    public_key: [u8; 32],
    reach: Option<kotton_crypto::reach_note::ReachNote>,
}

/// The longest one path is given to answer. The dial settles on the first
/// acknowledgement whatever the others are doing, but with none — a vault
/// answered *sent*, or nothing did — it waits on every path, and the transport
/// sets no bound of its own; a relay that has gone quiet would otherwise hold
/// the sender's answer for as long as the connection stays half-open. The
/// outbox tries again, so a path cut short here loses a try, not a message.
const PATH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a message waiting in the outbox waits between tries:
/// [`Retry::DEFAULT`], or a flat `KOTTON_OUTBOX_RETRY_SECS` when that is set —
/// the seam a test uses to see a retry inside seconds rather than half a minute.
pub(crate) fn outbox_retry() -> Retry {
    std::env::var("KOTTON_OUTBOX_RETRY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(|s| Retry { base_secs: s, cap_secs: s })
        .unwrap_or(Retry::DEFAULT)
}

/// Where a share's bytes wait while they stream in (`kotton_msg::daemon::stream`):
/// a daemon object per range, beside the outbox (`outbox_shelf`).
const STREAMS_PREFIX: &str = "/network/streams/";

/// Build a host for one dispatch arm.
///
/// A free function rather than a constructor so the call sites read as passing a
/// capability, not constructing a service: `&msg_host(runtime, users, record_stores)` is the
/// join, spelled once per arm and nowhere else.
pub fn msg_host<'a>(
    runtime: &'a DeviceRuntime,
    users: &'a UserRegistry,
    record_stores: &'a crate::residency::RecordStores,
) -> DaemonMessageHost<'a> {
    DaemonMessageHost {
        runtime,
        users,
        record_stores,
    }
}

/// What a [`kotton_msg::daemon::outbox::Path`] holds on this node: a relay's
/// address, or the way this device's open door handed out — a value, not a
/// string, so the local network is checked once.
///
/// The local network is a value only an open door makes ([`LocalWay`]), not a
/// spelling, so no relay in anyone's note can be it and nothing needs to refuse one
/// that tries; and the way ends when the door shuts, so a dial does not ask the door
/// again.
///
/// [`LocalWay`]: kotton_device::LocalWay
pub(crate) enum Way {
    Relay(String),
    LocalNetwork(kotton_device::LocalWay),
}

/// What this node's own log says a path was: the relay, which is this node's
/// operator's to read, or only *the local network* — never the network key the way
/// carries, which is derived from the router and would say where the device was.
impl std::fmt::Display for Way {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Way::Relay(relay) => f.write_str(relay),
            Way::LocalNetwork(_) => f.write_str("the local network"),
        }
    }
}

/// How long the local network is listened to for a contact's door before a
/// dial. A door announces on opening and answers a query at once; this is the
/// time to hear it, and it is spent inside the path's own [`PATH_TIMEOUT`].
const HEAR_FOR: std::time::Duration = std::time::Duration::from_secs(2);

/// Hand `request` to the contact's door on the local network, if it is open there,
/// by the way this device's own door handed out: only a door whose knock this pair
/// derives, and nothing once this device's door has shut — the way ends with it
/// ([`kotton_device::LocalWay::hand_over`]).
async fn deliver_here(
    way: &kotton_device::LocalWay,
    key: &ed25519_dalek::SigningKey,
    contact_pub: &[u8; 32],
    request: &kotton_wire::ipc::ContactRequest,
) -> Result<kotton_wire::ipc::ContactResponse, String> {
    match tokio::time::timeout(PATH_TIMEOUT, way.hand_over(HEAR_FOR, key, contact_pub, request)).await {
        Ok(answer) => answer.map_err(|e| format!("{e}")),
        Err(_) => Err(format!("no answer within {}s", PATH_TIMEOUT.as_secs())),
    }
}

/// Judge `note` from `contact_did` by `member`, the card this node read for
/// them, at `now` — the card's rule ([`judge_reach_note`]) applied to a card
/// only when it is a contact's. No card, or one of another role, is no
/// contact's card — a fact about this node's cards, which change between the
/// mailbox rebuild that opened the door and this read, so that refusal is
/// tried again rather than settled until the next reach note version.
/// Under the key the card holds, never one the note or the envelope brought
/// with it: that key is what pairing authenticated.
fn judge_on_card(
    member: Option<&kotton_schemas::membership::Member>,
    note: &kotton_crypto::reach_note::ReachNote,
    contact_did: &str,
    now: u64,
) -> Result<kotton_crypto::reach_note::Kept, kotton_msg::daemon::messages::NotKept> {
    use kotton_msg::daemon::messages::NoteCard;
    let card = member
        .filter(|m| matches!(m.role, kotton_schemas::membership::Role::Contact))
        .map(|m| NoteCard { held: m.reach.as_ref(), key: &m.public_key });
    judge_reach_note(card, note, contact_did, now)
}

/// Every path a delivery is dialled on: each relay, and then — when this device's
/// own door handed out a way on the network it is on — the local network.
/// Finding a contact's door and being findable are one capability, so a closed
/// door neither announces nor looks.
pub(crate) fn contact_paths_from(
    relays: Vec<String>,
    here: Option<kotton_device::LocalWay>,
) -> Vec<kotton_msg::daemon::outbox::Path> {
    relays
        .into_iter()
        .map(Way::Relay)
        .chain(here.map(Way::LocalNetwork))
        .map(kotton_msg::daemon::outbox::Path::new)
        .collect()
}

/// Every relay a delivery is dialled at `now`: each relay of `reach` — the
/// note their card holds, or a co-member's roster carries — in their order,
/// and then `own_relay` — each once, and none blank. Nothing else on a card
/// routes — a stored card from before the note carries a `relay_url` that is
/// read by nobody.
pub(crate) fn contact_relays(
    reach: Option<&kotton_crypto::reach_note::ReachNote>,
    own_relay: &str,
    now: u64,
) -> Vec<String> {
    let mut relays: Vec<String> = Vec::new();
    let noted = reach.map(|n| n.relays_at(now)).unwrap_or_default();
    for relay in noted.into_iter().chain(std::iter::once(own_relay)) {
        let relay = relay.trim();
        if !relay.is_empty() && !relays.iter().any(|r| r == relay) {
            relays.push(relay.to_string());
        }
    }
    relays
}

#[cfg(test)]
mod tests {
    use super::{contact_paths_from, contact_relays, judge_on_card, Way};
    use kotton_crypto::reach_note::{self, RelayRef};
    use kotton_schemas::membership::Member;

    const NOW: u64 = 1_800_000_000;

    fn card(stored: serde_json::Value) -> Member {
        serde_json::from_value(stored).unwrap()
    }

    fn stored_card() -> serde_json::Value {
        serde_json::json!({
            "did": "did:key:z6MkBob",
            "public_key": vec![9u8; 32],
            "role": "contact",
            "admitted_by": "pairing",
            "added_at": "2026-09-06T00:00:00Z",
            "relay_url": "http://relay.bob.left",
        })
    }

    /// A contact's card is dialled from their note, and never from the
    /// `relay_url` a card stored before the note still carries.
    #[test]
    fn a_contacts_card_reads_the_relay_from_the_note_and_not_from_relay_url() {
        let own = "http://relay.mine";
        let old = card(stored_card());
        assert_eq!(contact_relays(old.reach.as_ref(), own, NOW), vec![own], "no note: this node's own relay");

        let bob = card(with_note(&["http://relay.bob.now"]));
        assert_eq!(contact_relays(bob.reach.as_ref(), own, NOW), vec!["http://relay.bob.now", own]);
        let expires_at = bob.reach.as_ref().unwrap().expires_at;
        assert_eq!(
            contact_relays(bob.reach.as_ref(), own, expires_at),
            vec![own],
            "an expired note is not dialled; the card falls back to this node's relay"
        );
    }

    /// Every relay in the note, in the person's order, then this node's own —
    /// each once, so two people on one relay dial it once.
    #[test]
    fn a_contact_is_dialled_at_every_relay_in_their_note_and_at_this_nodes_own_once_each() {
        let own = "http://relay.shared";
        let bob = card(with_note(&["http://relay.bob.first", "http://relay.shared", "http://relay.bob.second"]));
        assert_eq!(
            contact_relays(bob.reach.as_ref(), own, NOW),
            vec!["http://relay.bob.first", "http://relay.shared", "http://relay.bob.second"]
        );
        assert_eq!(contact_relays(card(stored_card()).reach.as_ref(), "", NOW), Vec::<String>::new(), "no relay anywhere: no path");
    }

    fn with_note(relays: &[&str]) -> serde_json::Value {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let relays: Vec<RelayRef> = relays.iter().map(|a| RelayRef { key: None, addr: a.to_string(), admit: None }).collect();
        let note = reach_note::next(None, "did:key:z6MkBob", &relays, &[], &key, NOW).unwrap();
        let mut stored = stored_card();
        stored["reach"] = serde_json::to_value(&note).unwrap();
        stored
    }

    /// No string in a contact's note names the local network: an entry spelled
    /// as the old sentinel was is one more relay, and without a way from this
    /// device's open door there is no local-network path at all.
    #[test]
    fn no_note_entry_is_the_local_network() {
        let own = "http://relay.mine";
        let bob = card(with_note(&["http://relay.bob.now", "the local network"]));
        let relays = contact_relays(bob.reach.as_ref(), own, NOW);
        assert_eq!(relays, vec!["http://relay.bob.now", "the local network", own]);
        let paths = contact_paths_from(relays, None);
        let ways: Vec<String> = paths
            .iter()
            .map(|p| match p.way::<Way>().expect("a way this node made") {
                Way::Relay(relay) => relay.clone(),
                Way::LocalNetwork(_) => panic!("a note entry became the local network"),
            })
            .collect();
        assert_eq!(ways, vec!["http://relay.bob.now", "the local network", own]);
        assert_eq!(format!("{:?}", paths[0]), "Path(..)", "a path's Debug names nothing");
    }

    /// **A door refusal that can clear is tried again, not settled until the next
    /// reach note version.**
    /// What the card says of a note from Bob, by what this node has read for
    /// him: no card, a card of another role, or a clock trailing his within the
    /// slack a clock explains is a refusal about this node, tried again; a
    /// clock past that slack, or a version older than the one held, is the
    /// card's verdict.
    #[test]
    fn a_card_not_yet_a_contacts_or_a_clock_behind_is_tried_again_and_an_older_version_is_a_verdict() {
        use kotton_crypto::reach_note::Kept;
        use kotton_msg::daemon::messages::NotKept;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let did = "did:key:z6MkBob";
        let mut stored = stored_card();
        stored["public_key"] = serde_json::to_value(key.verifying_key().to_bytes()).unwrap();
        let note = reach_note::next(None, did, &[], &[], &key, NOW).unwrap();

        let no_card = judge_on_card(None, &note, did, NOW);
        assert!(matches!(no_card, Err(NotKept::Failed(_))), "no card yet: {no_card:?}");
        let mut own_device = stored.clone();
        own_device["role"] = serde_json::json!("own-device");
        let not_a_contacts = judge_on_card(Some(&card(own_device)), &note, did, NOW);
        assert!(matches!(not_a_contacts, Err(NotKept::Failed(_))), "not a contact's card: {not_a_contacts:?}");

        let contact = card(stored.clone());
        // His note claims a life a day past the longest at this clock.
        let behind = note.expires_at - reach_note::MAX_NOTE_LIFETIME_SECS - 24 * 60 * 60;
        let clock = judge_on_card(Some(&contact), &note, did, behind);
        assert!(matches!(clock, Err(NotKept::Failed(_))), "a clock behind his: {clock:?}");
        let far_behind = behind - reach_note::CLOCK_BEHIND_SLACK_SECS;
        let past = judge_on_card(Some(&contact), &note, did, far_behind);
        assert!(matches!(past, Err(NotKept::Refused(_))), "past what a clock explains: {past:?}");
        assert_eq!(judge_on_card(Some(&contact), &note, did, NOW), Ok(Kept::Replaced));

        let newer = reach_note::next(Some(&note), did, &[], &["ab".repeat(32)], &key, NOW).unwrap();
        stored["reach"] = serde_json::to_value(&newer).unwrap();
        let older = judge_on_card(Some(&card(stored)), &note, did, NOW);
        assert!(matches!(older, Err(NotKept::Refused(_))), "an older version: {older:?}");
    }
}

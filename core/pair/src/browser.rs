// SPDX-License-Identifier: AGPL-3.0-or-later
//! The browser door of RFC-0078, run as RFC-0040's ceremony.
//!
//! A browser reaches the node through a gateway that relays frames it cannot
//! read (GW3). It holds no identity key (GW5); what it holds is a **per-device
//! Ed25519 key** it generated itself, registered once from a trusted device and
//! revocable like an SSH key. The question is how that key, and the node's, are
//! bound to a channel the gateway cannot open — and the answer already exists:
//! the committed ephemeral-X25519 handshake every device pairing runs.
//!
//! ```text
//! browser (joiner J)                                node (issuer I)
//! 1. → Hello   { v, sid }                            sid is J's, fresh; there is no offer
//!                                                    2. ← Commit { SHA-256(eph_I ‖ nonce_I) }
//! 3. → Reveal  { eph_J, nonce_J }
//!                                                    4. ← Reveal { eph_I, nonce_I }   J checks the commit
//!    both derive k_enc and the SAS
//! 5. → Sealed  BrowserHello   { device_pub, name, sig_J }        sig_J = Ed25519(device, "kotton:browser-device:v1" ‖ transcript)
//!                                                    6. ← Sealed BrowserWelcome { node_pub, label, known, sig_I }
//!                                                           sig_I = Ed25519(node, "kotton:browser-node:v1" ‖ transcript ‖ device_pub)
//!    J verifies sig_I; if it pinned a node, node_pub must be that node
//! 7. → Confirm { mac_J }
//!    known = false: the node shows the SAS on a trusted screen and waits for a human
//!                                                    8. ← Confirm { mac_I }      or Refused
//! established: → Sealed request … ← Sealed response, in strict alternation
//! ```
//!
//! **Two ways to be authenticated, one handshake.** A device key the node has
//! never seen is admitted the way a new device is: a human compares six digits
//! on the node's own screen and says yes, and the key is registered under the
//! name the browser gave. A key the node knows is admitted by its signature over
//! the transcript, with no human in the loop; the node's signature over the same
//! transcript, checked against the key the browser pinned at enrollment, is what
//! stops a gateway from standing in for the node on a later visit. Both
//! signatures bind the ephemeral keys, so neither can be replayed into another
//! session, and `k_enc` is fresh each time (forward secrecy, as for devices).
//!
//! **What the gateway sees**: four cleartext handshake frames carrying nothing
//! but ephemeral public values and MACs, then ciphertext. It cannot derive
//! `k_enc` (it has neither ephemeral secret), cannot forge either signature, and
//! cannot make a human on the node's screen say yes.
//!
//! **Sans-I/O.** Both state machines take a frame and return what to send or
//! what to ask. The node drives [`Issuer`] from an IPC handler; the browser
//! drives [`Joiner`] from a WebSocket in JavaScript through a `wasm32` build of
//! this crate, or from a Rust test through a real gateway.

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::channel::AeadChannel;
use crate::handshake::{
    commit, derive_session, verify_commitment, EnrollmentSide, PairEphemeral, PairSession,
    Transcript,
};
use crate::wire::{PairCommit, PairConfirm, PairHello, PairReveal};

/// The handshake version, transcript-bound via [`PairHello::v`].
pub const PROTOCOL_VERSION: u16 = 1;

// ── Frame tags ─────────────────────────────────────────────────────────────────
//
// One leading byte says what a frame is. JSON bodies for the handshake frames
// (the same structs the QUIC ceremony uses); raw AEAD ciphertext once sealed.
// A tagged binary frame is what a WebSocket carries natively and what a relay
// forwards without parsing.

/// `PairHello`, JSON.
pub const TAG_HELLO: u8 = 1;
/// `PairCommit`, JSON.
pub const TAG_COMMIT: u8 = 2;
/// `PairReveal`, JSON.
pub const TAG_REVEAL: u8 = 3;
/// `PairConfirm`, JSON.
pub const TAG_CONFIRM: u8 = 4;
/// AEAD ciphertext under `k_enc`.
pub const TAG_SEALED: u8 = 0x10;
/// The node declined; the body is a short UTF-8 reason. Terminal.
pub const TAG_REFUSED: u8 = 0x7f;

/// Largest frame either side will accept. Requests and responses are JSON;
/// file bodies travel base64 inside them, so this bounds one file chunk.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

const DEVICE_SIG_CONTEXT: &[u8] = b"kotton:browser-device:v1";
const NODE_SIG_CONTEXT: &[u8] = b"kotton:browser-node:v1";

/// The browser's first sealed frame: which device key it holds, what to call it,
/// and proof it holds it, bound to this transcript.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserHello {
    /// The browser's per-device Ed25519 public key.
    pub device_pub: [u8; 32],
    /// The name the browser proposes for itself ("Austin's phone"). Used only
    /// when the key is new; a known key keeps the name it was registered under.
    pub name: String,
    /// `Ed25519(device, "kotton:browser-device:v1" ‖ transcript)`, 64 bytes.
    pub sig: Vec<u8>,
}

/// The node's sealed reply: who it is, and whether it already knows this key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserWelcome {
    /// The node's Ed25519 public key. The browser pins it at enrollment and
    /// requires it on every later visit.
    pub node_pub: [u8; 32],
    /// The node's human label ("austin's PC"), for the browser's screen.
    pub label: String,
    /// `true` if `device_pub` is already registered: no SAS, the signatures
    /// authenticate. `false`: a human on the node's screen is about to be asked.
    pub known: bool,
    /// `Ed25519(node, "kotton:browser-node:v1" ‖ transcript ‖ device_pub)`.
    pub sig: Vec<u8>,
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + body.len());
    f.push(tag);
    f.extend_from_slice(body);
    f
}

fn split(frame: &[u8]) -> Result<(u8, &[u8])> {
    if frame.len() > MAX_FRAME_BYTES {
        bail!("browser frame too large ({} bytes)", frame.len());
    }
    match frame.split_first() {
        Some((tag, body)) => Ok((*tag, body)),
        None => bail!("empty browser frame"),
    }
}

fn expect_tag(frame: &[u8], want: u8) -> Result<&[u8]> {
    let (tag, body) = split(frame)?;
    if tag == TAG_REFUSED {
        bail!(
            "refused by the node: {}",
            String::from_utf8_lossy(body)
        );
    }
    if tag != want {
        bail!("unexpected browser frame tag {tag:#x}, wanted {want:#x}");
    }
    Ok(body)
}

fn json_frame<T: Serialize>(tag: u8, msg: &T) -> Result<Vec<u8>> {
    Ok(frame(tag, &serde_json::to_vec(msg)?))
}

fn device_sig_msg(transcript: &Transcript) -> Vec<u8> {
    let mut m = DEVICE_SIG_CONTEXT.to_vec();
    m.extend_from_slice(&transcript.to_bytes());
    m
}

fn node_sig_msg(transcript: &Transcript, device_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = NODE_SIG_CONTEXT.to_vec();
    m.extend_from_slice(&transcript.to_bytes());
    m.extend_from_slice(device_pub);
    m
}

fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| anyhow!("malformed public key"))?;
    let sig = Signature::from_slice(sig).map_err(|_| anyhow!("malformed signature"))?;
    vk.verify(msg, &sig)
        .map_err(|_| anyhow!("signature does not verify"))
}

/// A refusal frame the node sends instead of a confirm. Terminal.
pub fn refused(reason: &str) -> Vec<u8> {
    frame(TAG_REFUSED, reason.as_bytes())
}

// ── Joiner (the browser) ───────────────────────────────────────────────────────

/// What the browser should do after feeding a frame to [`Joiner::receive`].
#[derive(Debug)]
pub enum JoinerStep {
    /// Send this frame and wait for the next.
    Send(Vec<u8>),
    /// The session is derived and the node has identified itself. Show `sas`
    /// (only meaningful when `known` is false — the node's screen shows the same
    /// six digits and a human compares them), then send `send`.
    Sas {
        sas: u32,
        node_label: String,
        node_pub: [u8; 32],
        known: bool,
        send: Vec<u8>,
    },
    /// The node confirmed. Frames now go through [`Joiner::seal`] / [`Joiner::open`].
    Established,
}

enum JState {
    SentHello,
    SentReveal,
    SentDeviceHello,
    SentConfirm,
    Established,
    Failed,
}

/// The browser's side of the ceremony.
pub struct Joiner {
    state: JState,
    device: SigningKey,
    name: String,
    pinned_node: Option<[u8; 32]>,
    sid: [u8; 16],
    eph: PairEphemeral,
    nonce_j: [u8; 32],
    commitment: Option<[u8; 32]>,
    transcript: Option<Transcript>,
    session: Option<PairSession>,
    aead: Option<AeadChannel>,
    node_pub: Option<[u8; 32]>,
}

impl Joiner {
    /// Begin a ceremony as `device`, proposing `name`. `pinned_node` is the key
    /// learned at enrollment; `None` on the very first visit, when the SAS is
    /// what authenticates the node. Returns the joiner and its opening frame.
    pub fn start(device: SigningKey, name: impl Into<String>, pinned_node: Option<[u8; 32]>) -> (Self, Vec<u8>) {
        let mut sid = [0u8; 16];
        OsRng.fill_bytes(&mut sid);
        let mut nonce_j = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_j);
        let hello = json_frame(
            TAG_HELLO,
            &PairHello {
                v: PROTOCOL_VERSION,
                sid,
            },
        )
        .expect("PairHello serializes");
        (
            Self {
                state: JState::SentHello,
                device,
                name: name.into(),
                pinned_node,
                sid,
                eph: PairEphemeral::generate(),
                nonce_j,
                commitment: None,
                transcript: None,
                session: None,
                aead: None,
                node_pub: None,
            },
            hello,
        )
    }

    /// Feed the next frame from the node.
    pub fn receive(&mut self, frame: &[u8]) -> Result<JoinerStep> {
        let step = self.step(frame);
        if step.is_err() {
            self.state = JState::Failed;
        }
        step
    }

    fn step(&mut self, frame: &[u8]) -> Result<JoinerStep> {
        match self.state {
            JState::SentHello => {
                let c: PairCommit = serde_json::from_slice(expect_tag(frame, TAG_COMMIT)?)?;
                self.commitment = Some(c.commit);
                self.state = JState::SentReveal;
                Ok(JoinerStep::Send(json_frame(
                    TAG_REVEAL,
                    &PairReveal {
                        eph_pub: self.eph.public(),
                        nonce: self.nonce_j,
                    },
                )?))
            }
            JState::SentReveal => {
                let r: PairReveal = serde_json::from_slice(expect_tag(frame, TAG_REVEAL)?)?;
                let commitment = self.commitment.expect("commit recorded");
                if !verify_commitment(&commitment, &r.eph_pub, &r.nonce) {
                    bail!("the node's reveal does not open its commitment (possible interposer)");
                }
                let transcript = Transcript {
                    sid: self.sid,
                    commit: commitment,
                    eph_pub_i: r.eph_pub,
                    eph_pub_j: self.eph.public(),
                    nonce_i: r.nonce,
                    nonce_j: self.nonce_j,
                };
                let session = derive_session(&self.eph, &r.eph_pub, &transcript)?;
                let mut aead = AeadChannel::new(session.k_enc(), EnrollmentSide::Joiner);
                let hello = BrowserHello {
                    device_pub: self.device.verifying_key().to_bytes(),
                    name: self.name.clone(),
                    sig: self.device.sign(&device_sig_msg(&transcript)).to_bytes().to_vec(),
                };
                let sealed = aead.seal(&serde_json::to_vec(&hello)?)?;
                self.transcript = Some(transcript);
                self.session = Some(session);
                self.aead = Some(aead);
                self.state = JState::SentDeviceHello;
                Ok(JoinerStep::Send(frame_sealed(&sealed)))
            }
            JState::SentDeviceHello => {
                let body = expect_tag(frame, TAG_SEALED)?;
                let aead = self.aead.as_mut().expect("channel keyed");
                let welcome: BrowserWelcome = serde_json::from_slice(&aead.open(body)?)?;
                let transcript = self.transcript.as_ref().expect("transcript derived");
                let device_pub = self.device.verifying_key().to_bytes();
                verify(
                    &welcome.node_pub,
                    &node_sig_msg(transcript, &device_pub),
                    &welcome.sig,
                )
                .map_err(|e| anyhow!("the node's signature is bad: {e}"))?;
                if let Some(pinned) = self.pinned_node {
                    if pinned != welcome.node_pub {
                        bail!("a different node answered than the one this browser was enrolled with");
                    }
                }
                let session = self.session.as_ref().expect("session derived");
                let confirm = json_frame(
                    TAG_CONFIRM,
                    &PairConfirm {
                        mac: session.confirm_mac(EnrollmentSide::Joiner, transcript),
                    },
                )?;
                self.node_pub = Some(welcome.node_pub);
                self.state = JState::SentConfirm;
                Ok(JoinerStep::Sas {
                    sas: session.sas(),
                    node_label: welcome.label,
                    node_pub: welcome.node_pub,
                    known: welcome.known,
                    send: confirm,
                })
            }
            JState::SentConfirm => {
                let c: PairConfirm = serde_json::from_slice(expect_tag(frame, TAG_CONFIRM)?)?;
                let session = self.session.as_ref().expect("session derived");
                let transcript = self.transcript.as_ref().expect("transcript derived");
                if !session.verify_confirm(EnrollmentSide::Issuer, transcript, &c.mac) {
                    bail!("the node's confirmation MAC does not verify");
                }
                self.state = JState::Established;
                Ok(JoinerStep::Established)
            }
            JState::Established => bail!("handshake already complete; use seal/open"),
            JState::Failed => bail!("this ceremony already failed"),
        }
    }

    /// The node's key, once learned. Pin it.
    pub fn node_pub(&self) -> Option<[u8; 32]> {
        self.node_pub
    }

    /// Seal a request for the node. Only after [`JoinerStep::Established`].
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !matches!(self.state, JState::Established) {
            bail!("channel not established");
        }
        Ok(frame_sealed(&self.aead.as_mut().expect("keyed").seal(plaintext)?))
    }

    /// Open the node's reply.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if !matches!(self.state, JState::Established) {
            bail!("channel not established");
        }
        let body = expect_tag(frame, TAG_SEALED)?;
        self.aead.as_mut().expect("keyed").open(body)
    }
}

fn frame_sealed(ct: &[u8]) -> Vec<u8> {
    frame(TAG_SEALED, ct)
}

// ── Issuer (the node) ──────────────────────────────────────────────────────────

/// What the node should do after feeding a frame to [`Issuer::receive`].
#[derive(Debug)]
pub enum IssuerStep {
    /// Reply with this frame.
    Send(Vec<u8>),
    /// The browser has identified itself and its signature verified. Decide
    /// whether `device_pub` is known, then call [`Issuer::welcome`].
    DeviceHello {
        device_pub: [u8; 32],
        name: String,
        sas: u32,
    },
    /// The browser sent its confirmation and it verified. For a known key, call
    /// [`Issuer::accept`] now; for a new one, ask the human first and call
    /// `accept` on yes or reply with [`refused`] on no.
    JoinerConfirmed,
}

enum IState {
    AwaitHello,
    SentCommit,
    SentReveal,
    AwaitWelcomeDecision,
    SentWelcome,
    AwaitVerdict,
    Established,
    Failed,
}

/// The node's side of the ceremony.
pub struct Issuer {
    state: IState,
    node: SigningKey,
    label: String,
    eph: PairEphemeral,
    nonce_i: [u8; 32],
    sid: Option<[u8; 16]>,
    commitment: Option<[u8; 32]>,
    transcript: Option<Transcript>,
    session: Option<PairSession>,
    aead: Option<AeadChannel>,
    device: Option<(VerifyingKey, String)>,
}

impl Issuer {
    /// A node ready to answer one browser's `Hello`. `node` is the key the
    /// browser will pin; `label` is what its screen calls this node.
    pub fn new(node: SigningKey, label: impl Into<String>) -> Self {
        let mut nonce_i = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_i);
        Self {
            state: IState::AwaitHello,
            node,
            label: label.into(),
            eph: PairEphemeral::generate(),
            nonce_i,
            sid: None,
            commitment: None,
            transcript: None,
            session: None,
            aead: None,
            device: None,
        }
    }

    /// Feed the next frame from the browser.
    pub fn receive(&mut self, frame: &[u8]) -> Result<IssuerStep> {
        let step = self.step(frame);
        if step.is_err() {
            self.state = IState::Failed;
        }
        step
    }

    fn step(&mut self, frame: &[u8]) -> Result<IssuerStep> {
        match self.state {
            IState::AwaitHello => {
                let h: PairHello = serde_json::from_slice(expect_tag(frame, TAG_HELLO)?)?;
                if h.v != PROTOCOL_VERSION {
                    bail!("browser speaks handshake v{}, this node speaks v{PROTOCOL_VERSION}", h.v);
                }
                let commitment = commit(&self.eph.public(), &self.nonce_i);
                self.sid = Some(h.sid);
                self.commitment = Some(commitment);
                self.state = IState::SentCommit;
                Ok(IssuerStep::Send(json_frame(TAG_COMMIT, &PairCommit { commit: commitment })?))
            }
            IState::SentCommit => {
                let r: PairReveal = serde_json::from_slice(expect_tag(frame, TAG_REVEAL)?)?;
                let transcript = Transcript {
                    sid: self.sid.expect("sid recorded"),
                    commit: self.commitment.expect("commit recorded"),
                    eph_pub_i: self.eph.public(),
                    eph_pub_j: r.eph_pub,
                    nonce_i: self.nonce_i,
                    nonce_j: r.nonce,
                };
                let session = derive_session(&self.eph, &r.eph_pub, &transcript)?;
                self.aead = Some(AeadChannel::new(session.k_enc(), EnrollmentSide::Issuer));
                self.transcript = Some(transcript);
                self.session = Some(session);
                self.state = IState::SentReveal;
                Ok(IssuerStep::Send(json_frame(
                    TAG_REVEAL,
                    &PairReveal {
                        eph_pub: self.eph.public(),
                        nonce: self.nonce_i,
                    },
                )?))
            }
            IState::SentReveal => {
                let body = expect_tag(frame, TAG_SEALED)?;
                let aead = self.aead.as_mut().expect("keyed");
                let hello: BrowserHello = serde_json::from_slice(&aead.open(body)?)?;
                let transcript = self.transcript.as_ref().expect("transcript derived");
                verify(&hello.device_pub, &device_sig_msg(transcript), &hello.sig)
                    .map_err(|e| anyhow!("the browser's device signature is bad: {e}"))?;
                let vk = VerifyingKey::from_bytes(&hello.device_pub)
                    .map_err(|_| anyhow!("malformed device key"))?;
                if hello.name.trim().is_empty() || hello.name.len() > 64 {
                    bail!("a browser device name must be 1–64 bytes");
                }
                self.device = Some((vk, hello.name.clone()));
                self.state = IState::AwaitWelcomeDecision;
                Ok(IssuerStep::DeviceHello {
                    device_pub: hello.device_pub,
                    name: hello.name,
                    sas: self.session.as_ref().expect("session").sas(),
                })
            }
            IState::SentWelcome => {
                let c: PairConfirm = serde_json::from_slice(expect_tag(frame, TAG_CONFIRM)?)?;
                let session = self.session.as_ref().expect("session");
                let transcript = self.transcript.as_ref().expect("transcript");
                if !session.verify_confirm(EnrollmentSide::Joiner, transcript, &c.mac) {
                    bail!("the browser's confirmation MAC does not verify");
                }
                self.state = IState::AwaitVerdict;
                Ok(IssuerStep::JoinerConfirmed)
            }
            IState::AwaitWelcomeDecision => bail!("call welcome() before feeding the next frame"),
            IState::AwaitVerdict => bail!("call accept() or send refused() before feeding the next frame"),
            IState::Established => bail!("handshake already complete; use seal/open"),
            IState::Failed => bail!("this ceremony already failed"),
        }
    }

    /// Answer the browser's hello. `known` says whether its key is registered.
    pub fn welcome(&mut self, known: bool) -> Result<Vec<u8>> {
        if !matches!(self.state, IState::AwaitWelcomeDecision) {
            bail!("welcome() is only valid right after DeviceHello");
        }
        let transcript = self.transcript.as_ref().expect("transcript");
        let (vk, _) = self.device.as_ref().expect("device hello recorded");
        let device_pub = vk.to_bytes();
        let welcome = BrowserWelcome {
            node_pub: self.node.verifying_key().to_bytes(),
            label: self.label.clone(),
            known,
            sig: self.node.sign(&node_sig_msg(transcript, &device_pub)).to_bytes().to_vec(),
        };
        let sealed = self.aead.as_mut().expect("keyed").seal(&serde_json::to_vec(&welcome)?)?;
        self.state = IState::SentWelcome;
        Ok(frame_sealed(&sealed))
    }

    /// Release the node's confirmation: the browser is in. For a new key, call
    /// this only after the human said the digits match.
    pub fn accept(&mut self) -> Result<Vec<u8>> {
        if !matches!(self.state, IState::AwaitVerdict) {
            bail!("accept() is only valid after JoinerConfirmed");
        }
        let session = self.session.as_ref().expect("session");
        let transcript = self.transcript.as_ref().expect("transcript");
        let confirm = json_frame(
            TAG_CONFIRM,
            &PairConfirm {
                mac: session.confirm_mac(EnrollmentSide::Issuer, transcript),
            },
        )?;
        self.state = IState::Established;
        Ok(confirm)
    }

    /// The six digits this ceremony derived, to show beside the browser's.
    pub fn sas(&self) -> Option<u32> {
        self.session.as_ref().map(|s| s.sas())
    }

    /// The browser's device key and proposed name, once it has said hello.
    pub fn device(&self) -> Option<([u8; 32], &str)> {
        self.device.as_ref().map(|(vk, n)| (vk.to_bytes(), n.as_str()))
    }

    /// `true` once [`accept`](Self::accept) has run.
    pub fn is_established(&self) -> bool {
        matches!(self.state, IState::Established)
    }

    /// Open a sealed request from the browser.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if !self.is_established() {
            bail!("channel not established");
        }
        let body = expect_tag(frame, TAG_SEALED)?;
        self.aead.as_mut().expect("keyed").open(body)
    }

    /// Seal a response for the browser.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.is_established() {
            bail!("channel not established");
        }
        Ok(frame_sealed(&self.aead.as_mut().expect("keyed").seal(plaintext)?))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Drive one full ceremony in memory, the way a gateway would relay it.
    /// Returns both established ends and what the browser learned.
    fn run(device: &SigningKey, pinned: Option<[u8; 32]>, node: &SigningKey, known: bool) -> Result<(Joiner, Issuer, u32, u32)> {
        let (mut j, hello) = Joiner::start(device.clone(), "test phone", pinned);
        let mut i = Issuer::new(node.clone(), "test node");
        let commit = match i.receive(&hello)? { IssuerStep::Send(f) => f, s => panic!("{s:?}") };
        let reveal_j = match j.receive(&commit)? { JoinerStep::Send(f) => f, s => panic!("{s:?}") };
        let reveal_i = match i.receive(&reveal_j)? { IssuerStep::Send(f) => f, s => panic!("{s:?}") };
        let dev_hello = match j.receive(&reveal_i)? { JoinerStep::Send(f) => f, s => panic!("{s:?}") };
        let sas_i = match i.receive(&dev_hello)? {
            IssuerStep::DeviceHello { device_pub, name, sas } => {
                assert_eq!(device_pub, device.verifying_key().to_bytes());
                assert_eq!(name, "test phone");
                sas
            }
            s => panic!("{s:?}"),
        };
        let welcome = i.welcome(known)?;
        let (sas_j, confirm_j) = match j.receive(&welcome)? {
            JoinerStep::Sas { sas, node_label, node_pub, known: k, send } => {
                assert_eq!(node_label, "test node");
                assert_eq!(node_pub, node.verifying_key().to_bytes());
                assert_eq!(k, known);
                (sas, send)
            }
            s => panic!("{s:?}"),
        };
        match i.receive(&confirm_j)? { IssuerStep::JoinerConfirmed => {}, s => panic!("{s:?}") }
        let confirm_i = i.accept()?;
        match j.receive(&confirm_i)? { JoinerStep::Established => {}, s => panic!("{s:?}") }
        Ok((j, i, sas_j, sas_i))
    }

    #[test]
    fn an_honest_ceremony_agrees_on_the_sas_and_carries_sealed_frames_both_ways() {
        let device = key();
        let node = key();
        let (mut j, mut i, sas_j, sas_i) = run(&device, None, &node, false).unwrap();
        assert_eq!(sas_j, sas_i);
        assert!(sas_j < 1_000_000);
        assert_eq!(j.node_pub(), Some(node.verifying_key().to_bytes()));

        let req = j.seal(br#"{"ListFiles":{"user_id":"u","prefix":""}}"#).unwrap();
        assert_eq!(req[0], TAG_SEALED);
        assert_eq!(i.open(&req).unwrap(), br#"{"ListFiles":{"user_id":"u","prefix":""}}"#);
        let resp = i.seal(b"{\"Ok\":null}").unwrap();
        assert_eq!(j.open(&resp).unwrap(), b"{\"Ok\":null}");
    }

    #[test]
    fn a_returning_browser_is_admitted_by_signature_and_pins_its_node() {
        let device = key();
        let node = key();
        let pinned = node.verifying_key().to_bytes();
        let (_j, i, _, _) = run(&device, Some(pinned), &node, true).unwrap();
        assert!(i.is_established());
    }

    #[test]
    fn a_different_node_cannot_answer_a_pinned_browser() {
        let device = key();
        let node = key();
        let other = key();
        match run(&device, Some(node.verifying_key().to_bytes()), &other, true) {
            Err(err) => assert!(err.to_string().contains("different node"), "{err}"),
            Ok(_) => panic!("a pinned browser accepted a stranger"),
        }
    }

    #[test]
    fn a_tampered_frame_fails_the_ceremony_and_it_stays_failed() {
        let device = key();
        let node = key();
        let (mut j, hello) = Joiner::start(device, "p", None);
        let mut i = Issuer::new(node, "n");
        let mut commit = match i.receive(&hello).unwrap() { IssuerStep::Send(f) => f, _ => unreachable!() };
        // Flip a byte inside the JSON body: the commitment no longer opens.
        let n = commit.len() - 3;
        commit[n] = if commit[n] == b'1' { b'2' } else { b'1' };
        let reveal_j = j.receive(&commit).unwrap_or_else(|_| panic!("commit parses"));
        let reveal_j = match reveal_j { JoinerStep::Send(f) => f, _ => unreachable!() };
        let reveal_i = match i.receive(&reveal_j).unwrap() { IssuerStep::Send(f) => f, _ => unreachable!() };
        let err = j.receive(&reveal_i).unwrap_err();
        assert!(err.to_string().contains("commitment"), "{err}");
        assert!(j.receive(&reveal_i).unwrap_err().to_string().contains("already failed"));
    }

    #[test]
    fn a_refusal_from_the_node_is_terminal_for_the_browser() {
        let device = key();
        let node = key();
        let (mut j, hello) = Joiner::start(device, "p", None);
        let mut i = Issuer::new(node, "n");
        let commit = match i.receive(&hello).unwrap() { IssuerStep::Send(f) => f, _ => unreachable!() };
        let _ = j.receive(&commit).unwrap();
        let err = j.receive(&refused("nobody is waiting on the node")).unwrap_err();
        assert!(err.to_string().contains("nobody is waiting"), "{err}");
    }

    #[test]
    fn the_gateway_sees_no_key_material_in_the_clear() {
        // Every cleartext frame is a handshake message; everything after is sealed.
        let device = key();
        let node = key();
        let (mut j, hello) = Joiner::start(device.clone(), "p", None);
        let mut i = Issuer::new(node, "n");
        let commit = match i.receive(&hello).unwrap() { IssuerStep::Send(f) => f, _ => unreachable!() };
        let reveal_j = match j.receive(&commit).unwrap() { JoinerStep::Send(f) => f, _ => unreachable!() };
        let reveal_i = match i.receive(&reveal_j).unwrap() { IssuerStep::Send(f) => f, _ => unreachable!() };
        let dev_hello = match j.receive(&reveal_i).unwrap() { JoinerStep::Send(f) => f, _ => unreachable!() };
        for f in [&hello, &commit, &reveal_j, &reveal_i] {
            assert!(f[0] != TAG_SEALED);
            let text = String::from_utf8_lossy(&f[1..]);
            assert!(!text.contains("device_pub"), "handshake frames carry no device identity");
        }
        assert_eq!(dev_hello[0], TAG_SEALED);
        let device_pub_hex = device.verifying_key().to_bytes();
        assert!(!dev_hello.windows(32).any(|w| w == device_pub_hex), "device key never in the clear");
    }
}

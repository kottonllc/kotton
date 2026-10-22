// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network discovery implementations

pub mod dht;
pub mod mdns;
pub mod r#static;

pub use dht::DhtDiscovery;
pub use mdns::{
    advertise_pairing_offer, announce_door, browse_doors, browse_pairing_offers, DiscoveredOffer, DoorAnnouncement, HeardDoor,
    MdnsDiscovery, PairingOffer,
};
pub use r#static::StaticDiscovery;

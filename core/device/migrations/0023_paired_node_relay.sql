-- The relay a paired node reserves at, recorded beside its key (RFC-0083 R5:
-- the pair is the resolver). Learned from the node itself on every successful
-- connect (`NodeRelay`) and from the ceremony's handout for a gateway; NULL for
-- a peer never asked, which the dialer reads as "dial at my own relay".
ALTER TABLE paired_nodes ADD COLUMN relay_url TEXT;

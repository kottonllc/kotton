// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `fs` domain's behaviour, over a handle carrying only what it needs.
//!
//! Per `RFC-0060` this is the shape that replaces methods on a runtime
//! god-struct: [`Fs`] borrows one already-routed store and knows nothing about
//! users, keys, configuration, or the other domains.
//!
//! Sealing happens *inside* the store stack, which is why no key reaches here —
//! the handle is one of the two in RFC-0060's table that receive none.
//!




#[cfg(test)]
mod tests {
    use kotton_schemas::to_object_key;

    #[test]
    fn traversal_cannot_resolve_to_a_sibling_key() {
        assert_eq!(to_object_key("/notes/../../etc/identity"), "etc/identity");
        assert_eq!(to_object_key("/a/./b/../c"), "a/c");
    }

    #[test]
    fn separators_and_leading_slashes_normalise() {
        assert_eq!(to_object_key("/foo\\bar"), "foo/bar");
        assert_eq!(to_object_key("///foo///bar"), "foo/bar");
        assert_eq!(to_object_key("/"), "");
    }
}

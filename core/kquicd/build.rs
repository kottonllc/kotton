// SPDX-License-Identifier: AGPL-3.0-or-later
//! Embeds Windows version metadata so the OS firewall dialog / Task Manager name
//! this binary "Kotton" rather than a bare path. No-op off Windows; never fails the
//! build (a missing resource compiler only drops the metadata, logged as a warning).

fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set("ProductName", "Kotton");
        res.set("CompanyName", "Kotton LLC");
        res.set("FileDescription", "Kotton QUIC Gateway");
        res.set("LegalCopyright", "\u{a9} Kotton LLC");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Kotton version resource skipped: {e}");
        }
    }
}

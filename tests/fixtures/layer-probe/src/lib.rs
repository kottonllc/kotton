// SPDX-License-Identifier: AGPL-3.0-or-later
//! A guest that imports `kotton:app/layer-surface` and draws nothing.
//!
//! See `tests/fixtures/layer-probe/Cargo.toml` for why it exists. The call
//! below is never executed by any test — what is under test is whether this
//! component *instantiates*, which depends only on whether the host put the
//! interface in the linker.

use kotton_app::_generated::kotton::app::{
    layer_surface,
    surface::{InputEvent, Size, Surface},
};
use kotton_app::Guest;

struct LayerProbe;

impl Guest for LayerProbe {
    /// Ask for a `Background`. If the interface was withheld, this function
    /// never runs: the component fails to instantiate against a linker missing
    /// the import, which is the refusal the test asserts on.
    fn on_launch(
        _first_surface: kotton_app::surface::Surface,
        _args: Vec<(String, String)>,
    ) -> Result<(), String> {
        let _ = layer_surface::create_background(Size {
            width: 1280,
            height: 800,
        })?;
        Ok(())
    }

    fn on_message(_msg: String) -> Result<(), String> {
        Ok(())
    }

    fn on_terminate() -> Result<(), String> {
        Ok(())
    }

    fn launch() {}

    fn on_input(_surface: &Surface, _event: InputEvent) {}

    fn on_surface_error(_reason: String) {}
}

kotton_app::export_app!(LayerProbe);

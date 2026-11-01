// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Embeds the wEdge icon and version information in the Windows executable.

fn main() {
    let icon = "../../packaging/branding/generated/wedge.ico";
    println!("cargo:rerun-if-changed={icon}");
    // `cfg(windows)` here is the build host: the resource compiler only
    // exists there, and so does the winresource dependency.
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed(icon);
    }
}

#[cfg(windows)]
fn embed(icon: &str) {
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon(icon)
        .set("ProductName", "wEdge")
        .set("FileDescription", "wEdge web and application server")
        .set("CompanyName", "Alingan Patra")
        .set("LegalCopyright", "Copyright (c) OpenEdge Labs. Apache-2.0.");
    if let Err(e) = resource.compile() {
        // A missing resource compiler must not break the build; the binary
        // then simply has no icon.
        println!("cargo:warning=no Windows icon embedded: {e}");
    }
}

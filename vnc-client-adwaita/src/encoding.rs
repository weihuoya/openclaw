use vnc_client::encodings::Encoding;

pub fn build_encoding_list(preferred: &str) -> Vec<Encoding> {
    let preferred = preferred.to_lowercase();
    let mut encodings = Vec::new();

    match preferred.as_str() {
        "tight" => encodings.push(Encoding::Tight),
        "zrle" => encodings.push(Encoding::Zrle),
        "hextile" => encodings.push(Encoding::Hextile),
        "raw" => encodings.push(Encoding::Raw),
        "copyrect" => encodings.push(Encoding::CopyRect),
        "trle" => encodings.push(Encoding::Trle),
        "rre" => encodings.push(Encoding::Rre),
        "openh264" => encodings.push(Encoding::OpenH264),
        _ => encodings.push(Encoding::Tight),
    }

    // Fallback encodings (always include Raw as a safe last-resort option).
    for enc in [
        Encoding::Zrle,
        Encoding::Hextile,
        Encoding::CopyRect,
        Encoding::OpenH264,
        Encoding::Raw,
    ] {
        if !encodings.contains(&enc) {
            encodings.push(enc);
        }
    }

    encodings.push(Encoding::DesktopSize);
    encodings.push(Encoding::Cursor);
    encodings.push(Encoding::ContinuousUpdates);
    encodings.push(Encoding::Fence);

    encodings
}

use std::path::PathBuf;
use std::process::Command;

const DOMAIN: &str = "com.weiz.vnc-client-adwaita";
const DESKTOP_NAME: &str = "com.weiz.vnc-client-adwaita";

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let po_dir = manifest_dir.join("po");
    let locale_dir = manifest_dir.join("locale");
    let data_dir = manifest_dir.join("data");

    let mut compiled_any = false;

    if po_dir.exists() {
        for entry in std::fs::read_dir(&po_dir).expect("read po dir") {
            let entry = entry.expect("po entry");
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("po") {
                continue;
            }

            let lang = path
                .file_stem()
                .expect("po file name")
                .to_string_lossy()
                .to_string();
            let mo_dir = locale_dir.join(&lang).join("LC_MESSAGES");
            std::fs::create_dir_all(&mo_dir).expect("create mo dir");

            let mo_path = mo_dir.join(format!("{DOMAIN}.mo"));
            let status = Command::new("msgfmt")
                .arg("--output")
                .arg(&mo_path)
                .arg(&path)
                .status()
                .expect("msgfmt failed to execute");
            if status.success() {
                compiled_any = true;
                println!("cargo:rerun-if-changed={}", path.display());
            } else {
                panic!(
                    "msgfmt failed for {} (status: {:?})",
                    path.display(),
                    status.code()
                );
            }
        }
    }

    let desktop_in = data_dir.join(format!("{DESKTOP_NAME}.desktop.in"));
    let desktop_out = data_dir.join(format!("{DESKTOP_NAME}.desktop"));
    if desktop_in.exists() {
        let status = Command::new("msgfmt")
            .arg("--desktop")
            .arg("--template")
            .arg(&desktop_in)
            .arg("-d")
            .arg(&po_dir)
            .arg("-o")
            .arg(&desktop_out)
            .status()
            .expect("msgfmt --desktop failed to execute");
        if !status.success() {
            panic!(
                "msgfmt --desktop failed for {} (status: {:?})",
                desktop_in.display(),
                status.code()
            );
        }
        println!("cargo:rerun-if-changed={}", desktop_in.display());
        println!(
            "cargo:rerun-if-changed={}",
            po_dir.join("LINGUAS").display()
        );
    }

    // Compile GSettings schemas so that the local data directory can be used
    // during development without a system-wide installation.
    let gschema = data_dir.join(format!("{DESKTOP_NAME}.gschema.xml"));
    if gschema.exists() {
        let status = Command::new("glib-compile-schemas")
            .arg(&data_dir)
            .status()
            .expect("glib-compile-schemas failed to execute");
        if !status.success() {
            panic!(
                "glib-compile-schemas failed for {} (status: {:?})",
                data_dir.display(),
                status.code()
            );
        }
        println!("cargo:rerun-if-changed={}", gschema.display());
    }

    if compiled_any {
        println!("cargo:rerun-if-changed=po");
        println!("cargo:rerun-if-changed=build.rs");
    }
}

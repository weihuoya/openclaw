# vnc-client-adwaita

A simple VNC client built with **libadwaita** / GTK4 and Rust. It reuses the
`vnc-client` and `vnc-widget-gtk4` crates from this workspace and persists
connection settings with GSettings.

## Features

- Adwaita-style GTK4 UI (header bar, toast overlay, preferences dialog).
- Reuses `VncDisplay` from `vnc-widget-gtk4` for remote framebuffer rendering.
- Supports **no authentication** and **VNC password authentication**.
- Settings saved to GSettings:
  - host, port, username, auth method
  - preferred encoding, view-only, scale-to-fit
- Password is only kept in memory and is cleared from the UI after connecting.

## System dependencies

In addition to the existing GTK4/GStreamer dependencies for `vnc-widget-gtk4`,
you need **libadwaita** development files and **gettext** (for building the `.po`
translations into `.mo` files).

On Debian/Ubuntu:

```bash
sudo apt-get install -y libadwaita-1-dev gettext
```

On Fedora:

```bash
sudo dnf install libadwaita-devel gettext
```

## Build

```bash
cargo build -p vnc-client-adwaita
cargo run -p vnc-client-adwaita
```

`build.rs` automatically compiles the `.po` translations into `locale/`, generates the
`.desktop` file, and compiles `data/gschemas.compiled` from the `.gschema.xml`. No
system-wide schema installation is required for development.

If you prefer to run against an installed schema and locales instead, install them
as described below and run the application without `VNC_LOCALE_DIR` or
`GSETTINGS_SCHEMA_DIR`.

## Install the schema, locales, and desktop entry system-wide (optional)

```bash
sudo install -Dm644 vnc-client-adwaita/data/com.weiz.vnc-client-adwaita.gschema.xml \
    /usr/share/glib-2.0/schemas/
sudo glib-compile-schemas /usr/share/glib-2.0/schemas/

sudo install -Dm644 vnc-client-adwaita/data/com.weiz.vnc-client-adwaita.desktop \
    /usr/share/applications/com.weiz.vnc-client-adwaita.desktop

for mo in vnc-client-adwaita/locale/*/LC_MESSAGES/com.weiz.vnc-client-adwaita.mo; do
    [ -e "$mo" ] || continue
    lang=$(basename "$(dirname "$(dirname "$mo")")")
    sudo install -Dm644 "$mo" \
        /usr/share/locale/$lang/LC_MESSAGES/com.weiz.vnc-client-adwaita.mo
done
```

After this, the application can be run without `GSETTINGS_SCHEMA_DIR` or
`VNC_LOCALE_DIR`, and it will appear in the desktop launcher.

## Arch Linux (PKGBUILD)

A PKGBUILD for building an Arch Linux package is included in this directory:

```bash
cd vnc-client-adwaita
makepkg -si
```

This installs the `vnc-client-adwaita` binary, the GSettings schema, the icon,
the desktop entry, and the compiled locale files system-wide.
The GSettings schema will be compiled automatically by the `glib2` install hook.

### Build from the local source tree (with uncommitted changes)

`makepkg.sh` copies the current working tree into a temporary build directory and
runs `makepkg -efi --noconfirm` against it. This lets you package and install
changes that have not been committed yet, and it does not require a remote
`source` checkout.

```bash
cd vnc-client-adwaita
./makepkg.sh
```

The resulting `.pkg.tar.zst` is copied back into `vnc-client-adwaita/`. These
package files are ignored by Git.

If you are preparing sources for the AUR, regenerate `.SRCINFO` after any
PKGBUILD change:

```bash
cd vnc-client-adwaita
makepkg --printsrcinfo > .SRCINFO
```


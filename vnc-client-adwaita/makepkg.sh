#!/bin/bash
# Build and install the vnc-client-adwaita package from the LOCAL source tree.
# This script can be run from any directory.
#
# Options:
#   --keep-build       Use a persistent build directory ($script_dir/build by default)
#                      so cargo can reuse its target/ for incremental rebuilds.
#   --build-dir PATH   Use PATH as the build directory (implies --keep-build).
#   --clean            Remove the build directory and exit.

set -euo pipefail

keep_build=false
build_dir=""
clean_only=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-build)
            keep_build=true
            shift
            ;;
        --build-dir)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --build-dir requires a path argument." >&2
                exit 1
            fi
            build_dir="$2"
            keep_build=true
            shift 2
            ;;
        --clean)
            clean_only=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--keep-build] [--build-dir PATH] [--clean]"
            echo
            echo "Build and install the vnc-client-adwaita package from the local source tree."
            echo
            echo "Options:"
            echo "  --keep-build       Use a persistent build directory for incremental rebuilds."
            echo "  --build-dir PATH   Use PATH as the build directory (implies --keep-build)."
            echo "  --clean            Remove the build directory and exit."
            echo "  -h, --help         Show this help."
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Use --help for usage." >&2
            exit 1
            ;;
    esac
done

# Change to the directory containing this script.
script_dir="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$script_dir"

pkgname="vnc-client-adwaita"
repo_root="$(cd .. && pwd)"

if [[ -z "$build_dir" ]]; then
    if $keep_build; then
        build_dir="$script_dir/build"
    else
        build_dir="$(mktemp -d)"
    fi
fi

if $clean_only; then
    if [[ -d "$build_dir" ]]; then
        rm -rf "$build_dir"
        echo "==> Removed build directory: $build_dir"
    else
        echo "==> Build directory does not exist: $build_dir"
    fi
    exit 0
fi

if $keep_build; then
    echo "==> Using persistent build directory: $build_dir"
else
    echo "==> Using temporary build directory: $build_dir"
fi

# Only remove the build directory on exit if it is temporary.
if ! $keep_build; then
    trap 'rm -rf "$build_dir"' EXIT
fi

echo "==> Building ${pkgname} from local source tree..."

# Ensure .SRCINFO is in sync with PKGBUILD so local builds use current metadata.
makepkg --printsrcinfo > .SRCINFO

# Ensure the build directory exists before copying metadata into it.
mkdir -p "$build_dir"

# Copy PKGBUILD metadata into the build directory.
cp PKGBUILD .SRCINFO "$build_dir/"

# Copy/update the local repository into the makepkg source directory.
# We exclude target/ so that cargo can reuse it across builds when keeping the
# build directory.
mkdir -p "$build_dir/src"
rsync -a --delete \
    --exclude='.git' \
    --exclude='target/' \
    --exclude='*.pkg.tar.*' \
    --exclude='vnc-client-adwaita/locale' \
    --exclude='vnc-client-adwaita/data/com.weiz.vnc-client-adwaita.desktop' \
    --exclude='vnc-client-adwaita/data/gschemas.compiled' \
    "$repo_root/" "$build_dir/src/$pkgname/"

# Build and install the package using the pre-populated src directory.
#   -e: do not extract the source (use the local copy we just created)
#   -f: force rebuild
#   -i: install the package after building
#   --noconfirm: do not prompt for confirmation
#
# If the install step fails (e.g. sudo needs a TTY in a non-interactive
# environment), still copy the built package back to the script directory.
cd "$build_dir"
if ! makepkg -efi --noconfirm; then
    cp -f *.pkg.tar.* "$script_dir/" 2>/dev/null || true
    echo "==> Install failed, but package is available at: $script_dir"
    exit 1
fi

# Copy the built package back to the script directory so the user can keep it.
cp -f *.pkg.tar.* "$script_dir/" 2>/dev/null || true

echo "==> ${pkgname} installed successfully from local source."

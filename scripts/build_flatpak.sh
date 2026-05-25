#!/usr/bin/env bash
#
# Build the Sigillum Flatpak.
#
# Prerequisites (one-shot, install via your distro's package manager):
#   - flatpak
#   - flatpak-builder
#   - python3 (for flatpak-pip-generator)
#
# And the GNOME runtime + SDK matching the manifest:
#   flatpak install -y flathub org.gnome.Platform//47 org.gnome.Sdk//47
#
# Usage:
#   scripts/build_flatpak.sh                # incremental build + install --user
#   scripts/build_flatpak.sh --regen-deps   # regenerate python3-deps.yaml first
#   scripts/build_flatpak.sh --bundle       # build + produce .flatpak bundle
#   scripts/build_flatpak.sh --clean        # blow away the build dir
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLATPAK_DIR="$ROOT_DIR/packaging/flatpak"
BUILD_DIR="$ROOT_DIR/dist/flatpak-build"
REPO_DIR="$ROOT_DIR/dist/flatpak-repo"
APP_ID="io.github.sigillum"
MANIFEST="$FLATPAK_DIR/$APP_ID.yml"
DEPS_YAML="$FLATPAK_DIR/python3-deps.yaml"

want_regen=0
want_bundle=0
want_clean=0
for arg in "$@"; do
  case "$arg" in
    --regen-deps) want_regen=1 ;;
    --bundle)     want_bundle=1 ;;
    --clean)      want_clean=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if (( want_clean )); then
  rm -rf "$BUILD_DIR" "$REPO_DIR"
  echo "Cleaned $BUILD_DIR and $REPO_DIR"
  exit 0
fi

# ------------------------------------------------------------------
# 1. Regenerate Python dependency manifest if requested or missing.
# ------------------------------------------------------------------
if (( want_regen )) || [[ ! -f "$DEPS_YAML" ]]; then
  echo "[deps] regenerating $DEPS_YAML"
  if ! command -v flatpak-pip-generator >/dev/null 2>&1; then
    if [[ ! -x "$ROOT_DIR/scripts/.flatpak-pip-generator" ]]; then
      echo "[deps] downloading flatpak-pip-generator…"
      # Upstream renamed the file to .py; the old name is now a stub pointer.
      curl -fsSL \
        https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/master/pip/flatpak-pip-generator.py \
        -o "$ROOT_DIR/scripts/.flatpak-pip-generator"
      chmod +x "$ROOT_DIR/scripts/.flatpak-pip-generator"
    fi
    pipgen="$ROOT_DIR/scripts/.flatpak-pip-generator"
  else
    pipgen="$(command -v flatpak-pip-generator)"
  fi

  # Extract the runtime dependency list from pyproject.toml so the two stay
  # in sync. We deliberately exclude PyGObject (it lives in the GNOME runtime).
  deps=$(python3 - <<'PY'
import tomllib, pathlib, re
data = tomllib.loads((pathlib.Path("pyproject.toml")).read_text())
out = []
for spec in data["project"]["dependencies"]:
    name = re.split(r'[<>=!~ ]', spec, maxsplit=1)[0]
    if name.lower() == "pygobject":
        continue
    out.append(spec)
print(" ".join(out))
PY
  )
  echo "[deps] pip deps: $deps"

  pushd "$FLATPAK_DIR" >/dev/null
  "$pipgen" --yaml --output python3-deps $deps
  popd >/dev/null
  echo "[deps] done → $DEPS_YAML"
fi

if [[ ! -f "$DEPS_YAML" ]]; then
  echo "ERROR: $DEPS_YAML missing — run with --regen-deps first" >&2
  exit 1
fi

# ------------------------------------------------------------------
# 2. Build.
# ------------------------------------------------------------------
mkdir -p "$BUILD_DIR"

build_args=(
  --force-clean
  --user
  --install-deps-from=flathub
  --repo="$REPO_DIR"
)
(( want_bundle )) || build_args+=(--install)

echo "[build] flatpak-builder → $BUILD_DIR"
flatpak-builder "${build_args[@]}" "$BUILD_DIR" "$MANIFEST"

# ------------------------------------------------------------------
# 3. Optional bundle for distribution.
# ------------------------------------------------------------------
if (( want_bundle )); then
  out="$ROOT_DIR/dist/packages/sigillum.flatpak"
  mkdir -p "$(dirname "$out")"
  flatpak build-bundle "$REPO_DIR" "$out" "$APP_ID" master
  echo "[bundle] $out"
fi

echo "Done. Run with: flatpak run $APP_ID"

#!/usr/bin/env bash
# Install the offline kit made by make-offline-kit.sh. Run on the offline host, from the kit
# folder (it doesn't need the repo yet), as the user the scanner will run as:
#   bash install-offline-kit.sh [install-dir]
set -euo pipefail
KIT=$(cd "$(dirname "$0")" && pwd)
DEST=${1:-$HOME/sbom-project}
TAG=aquasec/trivy:sbom-pinned
CACHE=/root/.cache/trivy

echo "0/5 checking the kit"
(cd "$KIT" && sha256sum --quiet -c SHA256SUMS) || { echo "Kit files changed or are incomplete; rebuild the kit."; exit 1; }

echo "1/5 code -> $DEST"
if [ -d "$DEST/.git" ]; then
    git -C "$DEST" pull -q --ff-only "$KIT/sbom-project.bundle" main
else
    git clone -q "$KIT/sbom-project.bundle" "$DEST"
fi

echo "2/5 Trivy image"
docker load -q -i "$KIT/trivy-image.tar"
[ "$(docker image inspect --format '{{.Id}}' "$TAG")" = "$(cat "$KIT/trivy-image.id")" ] \
    || { echo "Loaded Trivy image doesn't match the kit; stopping."; exit 1; }

echo "3/5 Trivy vulnerability DBs"
docker volume create trivy-cache >/dev/null
docker run --rm -v trivy-cache:$CACHE -v "$KIT":/kit:ro --entrypoint sh "$TAG" \
    -c "rm -rf $CACHE/db $CACHE/java-db && tar xzf /kit/trivy-cache.tar.gz -C $CACHE"

echo "4/5 Python packages"
PYPATH=""
if python3 -c 'import pymongo' 2>/dev/null; then
    echo "  pymongo already installed"
else
    here=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    [ "$here" = "$(cat "$KIT/python-version.txt")" ] || \
        echo "  note: kit built with Python $(cat "$KIT/python-version.txt"), this host has $here"
    pipi() { python3 -m pip install -q --no-index --find-links "$KIT/wheels" -r "$DEST/requirements.txt" "$@"; }
    if python3 -m pip --version >/dev/null 2>&1 && { pipi 2>/dev/null || pipi --break-system-packages; }; then
        echo "  installed with pip"
    else
        # No pip on this host: unpack the wheels next to the code instead.
        mkdir -p "$DEST/vendor"
        for w in "$KIT"/wheels/*.whl; do python3 -m zipfile -e "$w" "$DEST/vendor"; done
        PYPATH="$DEST/vendor"
        PYTHONPATH="$PYPATH" python3 -c 'import pymongo' || { echo "Could not install pymongo."; exit 1; }
        echo "  no pip here; unpacked into $PYPATH (needs PYTHONPATH, below)"
    fi
fi

echo "5/5 MongoDB image"
if [ -f "$KIT/mongo-image.tar" ]; then docker load -q -i "$KIT/mongo-image.tar"
else echo "  not in the kit (use a MongoDB on the network via SBOM_MONGO_URI)"; fi

cat <<EOF

Installed. Settings for this host, as KEY=value lines in /etc/sbom/env (sudo, then chmod 600):
  SBOM_TRIVY_OFFLINE=1
  SBOM_TRIVY_IMAGE=$TAG
  SBOM_MONGO_URI=mongodb://...      (only if MongoDB isn't on this host)
${PYPATH:+  PYTHONPATH=$PYPATH
}
systemd reads that file. For a run by hand, load it into your shell first:
  set -a; source <(sudo cat /etc/sbom/env); set +a
  cd $DEST && python3 scan_all.py
EOF

#!/usr/bin/env bash
# Build a kit for installing the pipeline on a host with no internet (README, "Offline hosts").
# Run on a machine that has internet, Docker and this repo, e.g. sweri-node-01:
#   bash deploy/make-offline-kit.sh [output-dir] [--with-mongo]
# then copy the output folder to a USB stick.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${1:-$HOME/sbom-offline-kit}
WITH_MONGO=${2:-}
PINNED=$(sed -n 's/.*"\(aquasec\/trivy@sha256:[0-9a-f]*\)".*/\1/p' scan_all.py | head -1)
TAG=aquasec/trivy:sbom-pinned     # docker save/load can drop digests, so the kit uses a tag
CACHE=/root/.cache/trivy
mkdir -p "$OUT/wheels"

echo "1/5 code"
git bundle create "$OUT/sbom-project.bundle" --all
cp deploy/install-offline-kit.sh "$OUT/"

echo "2/5 Trivy image ($PINNED)"
docker pull -q "$PINNED" >/dev/null
docker tag "$PINNED" "$TAG"
docker save "$TAG" -o "$OUT/trivy-image.tar"
docker image inspect --format '{{.Id}}' "$TAG" > "$OUT/trivy-image.id"

echo "3/5 Trivy vulnerability DBs (refreshing first)"
docker run --rm -v trivy-cache:$CACHE "$TAG" image --download-db-only --no-progress
docker run --rm -v trivy-cache:$CACHE "$TAG" image --download-java-db-only --no-progress
docker run --rm -v trivy-cache:$CACHE -v "$OUT":/kit --entrypoint sh "$TAG" \
    -c "tar czf /kit/trivy-cache.tar.gz -C $CACHE db java-db"

echo "4/5 Python packages"
python3 -m pip download -q -d "$OUT/wheels" -r requirements.txt
python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' > "$OUT/python-version.txt"

if [ "$WITH_MONGO" = "--with-mongo" ]; then
    echo "5/5 MongoDB image"
    docker pull -q mongo:8.0 >/dev/null
    docker save mongo:8.0 -o "$OUT/mongo-image.tar"
else
    echo "5/5 MongoDB image skipped (add --with-mongo if the offline host needs its own)"
fi

(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > ../.sbom-sums.tmp)
mv "$OUT/../.sbom-sums.tmp" "$OUT/SHA256SUMS"
echo
du -sh "$OUT"
echo "Kit ready in $OUT. Vulnerability DB date:"
docker run --rm -v trivy-cache:$CACHE "$TAG" version 2>/dev/null | grep -A2 "Vulnerability DB" || true

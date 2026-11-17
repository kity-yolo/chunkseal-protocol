#!/usr/bin/env bash
set -euo pipefail

CHUNKSEAL_ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
CHUNKSEAL_PYTHON="${CHUNKSEAL_PYTHON:-python3}"
export PYTHONPATH="$CHUNKSEAL_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
CHUNKSEAL_V2_CLASSES="$(mktemp -d -t chunkseal-v2-vectors-XXXXXXXX)"
trap 'rm -rf -- "$CHUNKSEAL_V2_CLASSES"' EXIT

"$CHUNKSEAL_PYTHON" "$CHUNKSEAL_ROOT/tools/check-v2-vectors.py"
javac --release 17 -encoding UTF-8 -Xlint:all -Werror -d "$CHUNKSEAL_V2_CLASSES" \
  "$CHUNKSEAL_ROOT/reference/java/src/chunkseal/ChunkSeal.java" \
  "$CHUNKSEAL_ROOT/reference/java/test/chunkseal/V2DraftVectors.java"
java -cp "$CHUNKSEAL_V2_CLASSES" chunkseal.V2DraftVectors \
  "$CHUNKSEAL_ROOT/test-vectors/v2.properties"

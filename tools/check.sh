#!/usr/bin/env bash
set -euo pipefail

CHUNKSEAL_ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
CHUNKSEAL_PYTHON="${CHUNKSEAL_PYTHON:-python3}"
export PYTHONPATH="$CHUNKSEAL_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
CHUNKSEAL_CLASSES="$(mktemp -d -t chunkseal-check-XXXXXXXX)"
trap 'rm -rf -- "$CHUNKSEAL_CLASSES"' EXIT

"$CHUNKSEAL_PYTHON" -m unittest discover -s "$CHUNKSEAL_ROOT/tests" -v
javac --release 17 -encoding UTF-8 -Xlint:all -Werror -d "$CHUNKSEAL_CLASSES" \
  "$CHUNKSEAL_ROOT/reference/java/src/chunkseal/ChunkSeal.java" \
  "$CHUNKSEAL_ROOT/reference/java/test/chunkseal/ChunkSealTest.java"
"$CHUNKSEAL_PYTHON" "$CHUNKSEAL_ROOT/tools/interop.py" write "$CHUNKSEAL_CLASSES"
java -cp "$CHUNKSEAL_CLASSES" chunkseal.ChunkSealTest \
  "$CHUNKSEAL_ROOT/test-vectors/v1.properties" "$CHUNKSEAL_CLASSES"
"$CHUNKSEAL_PYTHON" "$CHUNKSEAL_ROOT/tools/interop.py" verify "$CHUNKSEAL_CLASSES"

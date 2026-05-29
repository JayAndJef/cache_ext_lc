#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y rclone zstd

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
# realpath is needed here due to an rclone quirk
DB_PATH=$(realpath $BASE_DIR/..)

BUCKET="cache-ext-artifact-data"

# The artifact bucket stores the LevelDB database as a single zstd-compressed
# tarball (leveldb.tar.zst, ~68 GiB) that extracts to a top-level "leveldb/"
# directory of .ldb files. We stream-download and extract in one pipe so the
# 68 GiB tarball never has to land on disk alongside the ~110 GiB extracted DB
# (the machine only has ~170 GiB free).
TARBALL="leveldb.tar.zst"
DEST="${DB_PATH}/leveldb"

if [ -f "${DEST}/CURRENT" ]; then
	echo "LevelDB database already present at ${DEST}; skipping download."
	exit 0
fi

echo "Downloading and extracting LevelDB database to ${DEST}..."
rclone cat --gcs-anonymous ":gcs:${BUCKET}/${TARBALL}" \
	| zstd -dc \
	| tar -xf - -C "${DB_PATH}"

if [ ! -f "${DEST}/CURRENT" ]; then
	echo "Error: extraction finished but ${DEST}/CURRENT not found." >&2
	exit 1
fi

echo "LevelDB database ready at ${DEST}."

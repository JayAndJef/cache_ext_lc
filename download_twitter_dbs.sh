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
CLUSTERS=(17 18 24 34 52)

# Like download_dbs.sh, every artifact is a zstd-compressed tarball that we
# stream-download and extract in one pipe so the compressed tarball never has
# to land on disk alongside the extracted data.

# Twitter trace files. The tarball contains traces for many more clusters than
# the five used in the paper's Figure 8, so extract only the ones we need.
TRACES_DEST="${DB_PATH}/twitter-traces"
if [ -f "${TRACES_DEST}/cluster17_bench.txt" ]; then
	echo "Twitter traces already present at ${TRACES_DEST}; skipping download."
else
	echo "Downloading and extracting Twitter traces to ${TRACES_DEST}..."
	WANTED=()
	for cluster in "${CLUSTERS[@]}"; do
		WANTED+=("--wildcards" "twitter-traces/cluster${cluster}_*")
	done
	rclone cat --gcs-anonymous ":gcs:${BUCKET}/twitter-traces.tar.zst" \
		| zstd -dc \
		| tar -xf - -C "${DB_PATH}" "${WANTED[@]}"
fi
for cluster in "${CLUSTERS[@]}"; do
	if [ ! -s "${TRACES_DEST}/cluster${cluster}_bench.txt" ]; then
		echo "Error: ${TRACES_DEST}/cluster${cluster}_bench.txt missing or empty." >&2
		exit 1
	fi
done

# Pre-initialized per-cluster LevelDB databases (no init_leveldb step needed).
for cluster in "${CLUSTERS[@]}"; do
	DEST="${DB_PATH}/leveldb_twitter_cluster${cluster}_db"
	if [ -f "${DEST}/CURRENT" ]; then
		echo "Cluster ${cluster} database already present at ${DEST}; skipping."
		continue
	fi
	echo "Downloading and extracting cluster ${cluster} database to ${DEST}..."
	rclone cat --gcs-anonymous ":gcs:${BUCKET}/leveldb_twitter_cluster${cluster}_db.tar.zst" \
		| zstd -dc \
		| tar -xf - -C "${DB_PATH}"
	if [ ! -f "${DEST}/CURRENT" ]; then
		echo "Error: extraction finished but ${DEST}/CURRENT not found." >&2
		exit 1
	fi
done

echo "Twitter artifacts ready:"
du -sh "${TRACES_DEST}" "${DB_PATH}"/leveldb_twitter_cluster*_db

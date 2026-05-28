#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y rclone

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
# realpath is needed here due to an rclone quirk
DB_PATH=$(realpath $BASE_DIR/..)

BUCKET="cache-ext-artifact-data"

cd "$DB_PATH"

echo "Downloading LevelDB database..."
rclone copy --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb "${DB_PATH}/leveldb/"
rclone check --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb "${DB_PATH}/leveldb/"

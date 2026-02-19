#!/bin/bash

set -e

echo "Cleaning up BPF maps..."

EXCLUDE_NAMES="libbpf_global|pid_iter.rodata|libbpf_det_bind"

bpftool map list | grep -E "^[0-9]+:" | while read -r line; do
    MAP_ID=$(echo "$line" | awk '{print $1}' | tr -d ':')
    MAP_NAME=$(echo "$line" | awk '{print $3}')
    
    if echo "$MAP_NAME" | grep -qE "$EXCLUDE_NAMES"; then
        echo "  Skipping $MAP_NAME (id $MAP_ID)"
        continue
    fi
    
    echo "  Deleting map $MAP_NAME (id $MAP_ID)"
    bpftool map delete id "$MAP_ID" 2>/dev/null || true
done

echo "BPF map cleanup complete!"


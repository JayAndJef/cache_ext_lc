#!/bin/bash

# Script to calculate cache hit ratios from model_run_results and normal_run_results
# Hit ratio = (accesses - insertions) / accesses

set -e

# Directories
MODEL_DIR="/home/jaydenq/research/model_run_results/randomread"
NORMAL_DIR="/home/jaydenq/research/normal_run_results/randomread"

# Function to calculate hit ratio for a single run
calculate_hit_ratio() {
    local access_file="$1"
    local insertion_file="$2"

    # Count lines (subtract 1 for header)
    local accesses=$(wc -l < "$access_file")
    accesses=$((accesses - 1))

    local insertions=$(wc -l < "$insertion_file")
    insertions=$((insertions - 1))

    # Calculate hit ratio: (accesses - insertions) / accesses
    # Using awk for floating point arithmetic
    if [ "$accesses" -gt 0 ]; then
        local hit_ratio=$(awk "BEGIN {printf \"%.6f\", ($accesses - $insertions) / $accesses}")
        echo "$hit_ratio"
    else
        echo "0"
    fi
}

# Function to process all runs in a directory
process_directory() {
    local dir="$1"
    local label="$2"

    echo "Processing $label runs from: $dir" >&2
    echo "================================================" >&2
    
    local total_hit_ratio=0
    local count=0
    
    # Find all access files and match them with insertion files
    for access_file in "$dir"/cache_access_*_access.csv; do
        if [ ! -f "$access_file" ]; then
            continue
        fi
        
        # Extract timestamp from filename
        # Format: cache_access_20260218_231418_access.csv
        local basename=$(basename "$access_file")
        local timestamp=$(echo "$basename" | sed 's/cache_access_\(.*\)_access.csv/\1/')
        
        # Find corresponding insertion file
        local insertion_file="$dir/cache_insertion_${timestamp}_insertion.csv"
        
        if [ ! -f "$insertion_file" ]; then
            echo "Warning: No matching insertion file for $access_file" >&2
            continue
        fi

        # Calculate hit ratio for this run
        local hit_ratio=$(calculate_hit_ratio "$access_file" "$insertion_file")

        # Get line counts for display
        local accesses=$(wc -l < "$access_file")
        accesses=$((accesses - 1))
        local insertions=$(wc -l < "$insertion_file")
        insertions=$((insertions - 1))

        echo "Run $timestamp:" >&2
        echo "  Accesses:   $accesses" >&2
        echo "  Insertions: $insertions" >&2
        echo "  Hit Ratio:  $hit_ratio" >&2
        echo "" >&2
        
        # Add to total for averaging
        total_hit_ratio=$(awk "BEGIN {print $total_hit_ratio + $hit_ratio}")
        count=$((count + 1))
    done

    # Calculate average
    if [ "$count" -gt 0 ]; then
        local avg_hit_ratio=$(awk "BEGIN {printf \"%.6f\", $total_hit_ratio / $count}")
        echo "================================================" >&2
        echo "Average Hit Ratio ($label): $avg_hit_ratio" >&2
        echo "Number of runs: $count" >&2
        echo "" >&2
        echo "$avg_hit_ratio"
    else
        echo "No runs found in $dir" >&2
        echo "0"
    fi
}

# Main execution
echo ""
echo "========================================"
echo "Cache Hit Ratio Analysis"
echo "========================================"
echo ""

# Process model runs
model_avg=$(process_directory "$MODEL_DIR" "Model")

# Process normal runs
normal_avg=$(process_directory "$NORMAL_DIR" "Normal")

# Summary
echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Model Run Average Hit Ratio:  $model_avg"
echo "Normal Run Average Hit Ratio: $normal_avg"
echo ""

# Calculate improvement
if [ "$normal_avg" != "0" ]; then
    improvement=$(awk "BEGIN {printf \"%.6f\", ($model_avg - $normal_avg) / $normal_avg * 100}")
    echo "Improvement: $improvement%"
fi


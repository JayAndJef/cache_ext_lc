# shellcheck shell=bash
# Per-cluster cgroup sizing for the Twitter eval -- the single source of truth.
#
# SOURCED (not executed) by collect_traces.sh, run_heuristic_eval.sh and
# run_ml_sampling_eval.sh so all three size every cluster IDENTICALLY. That
# identity is not cosmetic:
#   - tracer collection vs eval must match for TRAIN/SERVE PARITY -- the reuse
#     labels and inode-level features a per-cluster model learns are a function
#     of the memory pressure it saw, so serving it at a different size is skew;
#   - the heuristic baselines (run_heuristic_eval.sh) and the model policies
#     (run_ml_sampling_eval.sh) must match so the comparison is at the same
#     memory size, not different ones.
# Edit a cluster's pair here once and all three scripts pick it up.
#
# Format: CGROUP_BY_CLUSTER[<cluster>]="<size-pct> <floor-mib>"
#   size-pct  : cgroup limit as a percent of that cluster's DB size (+20 MiB),
#               computed per config by bench_twitter_trace.py.
#   floor-mib : minimum cgroup limit in MiB. It DOMINATES when 15% of the DB is
#               below it, which over-provisions small clusters: e.g. cluster 18's
#               DB is ~151 MiB, so a 192 MiB floor caches the whole DB and the
#               policy never evicts. Lower the floor for those clusters so they
#               see real eviction pressure. Approx DB sizes: 17=920M, 18=151M,
#               24=456M, 34=5.9G, 52=2.5G (34/52 are pct-dominated; 17/18/24 are
#               floor-dominated).
# Sizing tuned so each cluster's tracer eviction rate lands in [900,1300] evt/s
# (goal 1100 +-200). size-pct is the only knob (multiples of 5%); floor-mib is
# kept at 32 so it never binds (percent always controls). Round-1 measured @ the
# unrounded pct then relabeled to nearest 5% (<2% shift, rate ~unchanged):
#   17: 1254 @38%->FROZEN 40%   34: 1031 @56%->FROZEN 55%   52: 1148 @36%->FROZEN 35%
# Round-2: 24: 1462@78%->85% = 1224 FROZEN.  18: 5137@41%->60% = 1667 still HIGH.
# Round-3: 18@70% = 568 LOW (knee is steep: 60->70% is exp ~-8.4).
# Round-4: 18 -> 65% (only multiple-of-5 in the 60/70% bracket; interp ~960).
# OVERRIDE: 10%/70-floor for all clusters, to match results-old + protect@10/70
# (same sizing -> apples-to-apples). Effective MiB: 17=112 18=70 24=70 34=614 52=266.
declare -A CGROUP_BY_CLUSTER=(
	[17]="10 70"
	[18]="10 70"
	[24]="10 70"
	[34]="10 70"
	[52]="10 70"
)

# require_cluster_cgroups <cluster>... -- hard-fail (before any expensive setup)
# if any requested cluster has no entry above. Call right after parsing
# --clusters so an unsized cluster can't silently fall back to a default.
require_cluster_cgroups() {
	local c missing=""
	for c in "$@"; do
		[ -n "${CGROUP_BY_CLUSTER[$c]+x}" ] || missing="$missing $c"
	done
	if [ -n "$missing" ]; then
		echo "Error: no cgroup sizing for cluster(s):$missing" >&2
		echo "Add them to lc-eval/twitter/cgroup_sizes.sh as [<cluster>]=\"<pct> <floor-mib>\"." >&2
		exit 1
	fi
}

# cgroup_table_tokens <cluster>... -- echo "<cluster>:<pct>:<floor>" tokens
# (space-separated) for embedding the per-cluster sizing into meta/manifest JSON.
cgroup_table_tokens() {
	local c pct floor out=""
	for c in "$@"; do
		read -r pct floor <<< "${CGROUP_BY_CLUSTER[$c]}"
		out="$out $c:$pct:$floor"
	done
	echo "${out# }"
}

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
declare -A CGROUP_BY_CLUSTER=(
	[17]="15 192"
	[18]="15 120"
	[24]="15 192"
	[34]="15 192"
	[52]="15 192"
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

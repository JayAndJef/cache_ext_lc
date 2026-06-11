#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define UNKNOWN_DELTA_NS 0xffffffffffffffffULL
#define UNKNOWN_OFFSET_DELTA 0xffffffffU

// Skip-in-place protection: eviction scans the FIFO list head-first (oldest
// first) and classifies each folio. Predicted-reused folios are rotated to
// the list tail (a second chance -- CLOCK-style); everything else evictable
// is evicted, until exactly the requested number of victims is gathered. If
// the scan cannot gather enough (nearly everything protected/unevictable), a
// fallback pass evicts head-first ignoring the model so reclaim always makes
// progress. No oversampling: the scan stops as soon as the quota is met.

#define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

//////////
// Maps //
//////////

// Single FIFO list for all pages (no insertion-time placement).
__u64 sampling_list;

struct tracer_page_key {
	__u32 dev;
	__u64 ino;
	__u64 offset;
};

struct tracer_page_state {
	__u64 first_access_time;
	__u64 prev_access_time;
	__u64 last_access_time;
	__u64 last_file_offset;
	__u64 file_size;
	__u64 last_access_delta;
	__u64 prev_access_delta;
	__u32 frequency;
};

struct file_key {
	__u32 dev;
	__u64 ino;
};

struct file_state {
	__u64 last_index;
	__u64 prev_access_time;
	__u64 last_access_time;
	__u64 last_access_delta;
	__u64 prev_access_delta;
	__u32 hotness_ema;
	__u32 last_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1000000);
	__type(key, struct tracer_page_key);
	__type(value, struct tracer_page_state);
} per_folio_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 50000);
	__type(key, struct file_key);
	__type(value, struct file_state);
} per_file_map SEC(".maps");

///////////////////
// Model Loading //
///////////////////

#define NUM_MODEL_FEATURES 9
#define MAX_BINS 10

enum model_features {
	PD = 0,  // page delta t
	SZ = 1,  // size
	FQ = 2,  // page hotness (frequency)
	SD = 3,  // sequential distance
	PD2 = 4, // page delta t 2
	ID = 5,  // inode delta t
	ID2 = 6, // inode delta t 2
	IE = 7,  // inode hotness (ema)
	TSA = 8, // time since last access at eviction
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_MODEL_FEATURES);
	__type(key, __u32);
	__type(value, __u8);
} n_bins_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_MODEL_FEATURES);
	__type(key, __u32);
	__type(value, __u64[MAX_BINS]);
} bin_edges_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_MODEL_FEATURES);
	__type(key, __u32);
	__type(value, s64[MAX_BINS]);
} nn_weights_map SEC(".maps");

// Bias + decision threshold (quantized by weight_scale), loaded from JSON.
struct model_meta {
	s64 bias;
	s64 threshold;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct model_meta);
} model_meta_map SEC(".maps");

/////////////
// Helpers //
/////////////

static inline u32 get_folio_dev(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host || !folio->mapping->host->i_sb)
		return 0;
	return folio->mapping->host->i_sb->s_dev;
}

static inline u64 get_folio_ino(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return 0;
	return folio->mapping->host->i_ino;
}

static inline u64 get_folio_file_size(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return 0;
	return folio->mapping->host->i_size;
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio)
		return false;
	if (folio->mapping == NULL)
		return false;
	if (folio->mapping->host == NULL)
		return false;
	return inode_in_watchlist(folio->mapping->host->i_ino);
}

////////////
// Tracer //
////////////
// Maintains per_folio_map / per_file_map so the eviction-time classifier has
// the same features the fifo_lc tracer logged during training. Feature state
// is updated ONLY at folio_accessed -- never at insertion or eviction -- so
// features are pure functions of the access stream. This function must stay
// identical to the fifo_lc tracer's copy (train/serve parity lives here).
// No ring-buffer logging -- this is a deployment policy, not a data collector.

static inline void track_folio_access(struct folio *folio) {
	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 file_size = get_folio_file_size(folio);
	u64 index = folio->index;
	u64 timestamp = bpf_ktime_get_ns();

	struct tracer_page_key folio_key;
	__builtin_memset(&folio_key, 0, sizeof(folio_key));
	folio_key.dev = s_dev;
	folio_key.ino = i_ino;
	folio_key.offset = index;

	if (s_dev == 0 || i_ino == 0)
		return;

	struct file_key fkey;
	__builtin_memset(&fkey, 0, sizeof(fkey));
	fkey.dev = s_dev;
	fkey.ino = i_ino;

	struct tracer_page_state *page_state = bpf_map_lookup_elem(&per_folio_map, &folio_key);
	struct file_state *file_state = bpf_map_lookup_elem(&per_file_map, &fkey);

	u64 page_time_delta = UNKNOWN_DELTA_NS;
	bool has_page_delta = false;
	if (page_state) {
		if (timestamp >= page_state->last_access_time)
			page_time_delta = timestamp - page_state->last_access_time;
		has_page_delta = page_state->last_access_delta != UNKNOWN_DELTA_NS;
	}

	u64 inode_time_delta = UNKNOWN_DELTA_NS;
	bool has_inode_delta = false;
	if (file_state) {
		if (timestamp >= file_state->last_access_time)
			inode_time_delta = timestamp - file_state->last_access_time;
		has_inode_delta = file_state->last_access_delta != UNKNOWN_DELTA_NS;
	}

	u32 last_offset = UNKNOWN_OFFSET_DELTA;
	if (file_state) {
		u64 offset_diff = index > file_state->last_index ?
			index - file_state->last_index :
			file_state->last_index - index;
		if (offset_diff > UNKNOWN_OFFSET_DELTA)
			last_offset = UNKNOWN_OFFSET_DELTA;
		else
			last_offset = (u32)offset_diff;
	}

	u32 inode_hotness_ema = 1000;
	if (file_state) {
		u64 half_life_ns = 1000000000ULL;
		if (!has_inode_delta) {
			inode_hotness_ema = file_state->hotness_ema;
		} else if (inode_time_delta == 0) {
			inode_hotness_ema = file_state->hotness_ema + 1000;
		} else {
			u64 decay;
			if (inode_time_delta < half_life_ns) {
				u64 ratio = (inode_time_delta * 1000) / half_life_ns;
				decay = 1000 - (ratio / 2);
			} else {
				u64 half_lives = inode_time_delta / half_life_ns;
				if (half_lives > 10)
					decay = 0;
				else
					decay = 1000 >> half_lives;
			}
			u64 decayed = ((u64)file_state->hotness_ema * decay) / 1000;
			inode_hotness_ema = (u32)(decayed + 1000);
		}
	}

	u32 frequency = 1000;
	if (page_state) {
		if (has_page_delta && page_time_delta > 0) {
			u64 half_life_ns = 1000000000ULL;
			u64 decay;
			if (page_time_delta < half_life_ns) {
				u64 ratio = (page_time_delta * 1000) / half_life_ns;
				decay = 1000 - (ratio / 2);
			} else {
				u64 half_lives = page_time_delta / half_life_ns;
				if (half_lives > 10)
					decay = 0;
				else
					decay = 1000 >> half_lives;
			}
			u64 decayed = ((u64)page_state->frequency * decay) / 1000;
			frequency = (u32)(decayed + 1000);
		} else if (has_page_delta) {
			frequency = page_state->frequency + 1000;
		}
	}

	struct tracer_page_state new_page_state;
	if (page_state) {
		new_page_state.first_access_time = page_state->first_access_time;
		new_page_state.prev_access_time = page_state->last_access_time;
		new_page_state.prev_access_delta = page_state->last_access_delta;
	} else {
		new_page_state.first_access_time = timestamp;
		new_page_state.prev_access_time = 0;
		new_page_state.prev_access_delta = UNKNOWN_DELTA_NS;
	}
	new_page_state.last_access_time = timestamp;
	new_page_state.last_file_offset = index;
	new_page_state.file_size = file_size;
	new_page_state.last_access_delta = page_state ? page_time_delta : UNKNOWN_DELTA_NS;
	new_page_state.frequency = frequency;

	bpf_map_update_elem(&per_folio_map, &folio_key, &new_page_state, BPF_ANY);

	struct file_state new_file_state = {
		.last_index = index,
		.last_offset = last_offset,
		.prev_access_time = file_state ? file_state->last_access_time : 0,
		.last_access_time = timestamp,
		.last_access_delta = file_state ? inode_time_delta : UNKNOWN_DELTA_NS,
		.prev_access_delta = file_state ? file_state->last_access_delta : UNKNOWN_DELTA_NS,
		.hotness_ema = inode_hotness_ema,
	};
	bpf_map_update_elem(&per_file_map, &fkey, &new_file_state, BPF_ANY);
}

///////////////////
// ML Functions  //
///////////////////

// Discretize a feature value using interior bin edges.
static inline __u8 discretize_feature(__u64 value, __u64 *bin_edges, __u8 n_bins) {
	__u8 n_interior_edges = n_bins - 1;

	if (n_interior_edges > 0 && value < bin_edges[0]) return 0;
	if (n_interior_edges > 1 && value < bin_edges[1]) return 1;
	if (n_interior_edges > 2 && value < bin_edges[2]) return 2;
	if (n_interior_edges > 3 && value < bin_edges[3]) return 3;
	if (n_interior_edges > 4 && value < bin_edges[4]) return 4;
	if (n_interior_edges > 5 && value < bin_edges[5]) return 5;
	if (n_interior_edges > 6 && value < bin_edges[6]) return 6;
	if (n_interior_edges > 7 && value < bin_edges[7]) return 7;
	if (n_interior_edges > 8 && value < bin_edges[8]) return 8;

	return n_bins - 1;
}

// Sum of per-bin weights over the 9 eviction-time features (the model logit
// before bias). Returns S64_MAX if the folio has no tracked state yet.
static inline s64 compute_feature_score(struct folio *folio) {
	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 index = folio->index;

	if (s_dev == 0 || i_ino == 0)
		return S64_MAX;

	struct tracer_page_key folio_key;
	__builtin_memset(&folio_key, 0, sizeof(folio_key));
	folio_key.dev = s_dev;
	folio_key.ino = i_ino;
	folio_key.offset = index;

	struct file_key fkey;
	__builtin_memset(&fkey, 0, sizeof(fkey));
	fkey.dev = s_dev;
	fkey.ino = i_ino;

	struct tracer_page_state *page_state = bpf_map_lookup_elem(&per_folio_map, &folio_key);
	struct file_state *file_state = bpf_map_lookup_elem(&per_file_map, &fkey);

	if (!page_state || !file_state)
		return S64_MAX;

	u64 now = bpf_ktime_get_ns();
	u64 tsa = now >= page_state->last_access_time ?
		now - page_state->last_access_time : 0;

	u64 raw_features[NUM_MODEL_FEATURES];
	raw_features[PD] = page_state->last_access_delta;
	raw_features[SZ] = page_state->file_size;
	raw_features[FQ] = page_state->frequency;
	raw_features[SD] = file_state->last_offset;
	raw_features[PD2] = page_state->prev_access_delta;
	raw_features[ID] = file_state->last_access_delta;
	raw_features[ID2] = file_state->prev_access_delta;
	raw_features[IE] = file_state->hotness_ema;
	raw_features[TSA] = tsa;

	s64 score = 0;

#define PROCESS_FEATURE(feat_idx) \
	do { \
		u32 idx = (feat_idx); \
		__u8 *n_bins_ptr = bpf_map_lookup_elem(&n_bins_map, &idx); \
		if (n_bins_ptr) { \
			__u64 (*bin_edges)[MAX_BINS] = bpf_map_lookup_elem(&bin_edges_map, &idx); \
			if (bin_edges) { \
				s64 (*weights)[MAX_BINS] = bpf_map_lookup_elem(&nn_weights_map, &idx); \
				if (weights) { \
					__u8 n_bins = *n_bins_ptr; \
					if (n_bins > 0 && n_bins <= MAX_BINS) { \
						__u8 bin = discretize_feature(raw_features[feat_idx], *bin_edges, n_bins); \
						if (bin >= MAX_BINS) bin = MAX_BINS - 1; \
						score += (*weights)[bin]; \
					} \
				} \
			} \
		} \
	} while (0)

	PROCESS_FEATURE(0);
	PROCESS_FEATURE(1);
	PROCESS_FEATURE(2);
	PROCESS_FEATURE(3);
	PROCESS_FEATURE(4);
	PROCESS_FEATURE(5);
	PROCESS_FEATURE(6);
	PROCESS_FEATURE(7);
	PROCESS_FEATURE(8);

#undef PROCESS_FEATURE

	return score;
}

/////////////////////
// Policy Handlers //
/////////////////////

s32 BPF_STRUCT_OPS_SLEEPABLE(protect_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: protect_init\n");
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: fifo_ml_protect initialized\n");
	return 0;
}

// Insertion mutates NO feature state: feature maps are pure functions of the
// access stream, so the model is independent of insertion dynamics (readahead,
// evict/re-insert cycles of whichever policy collected the training data).
void BPF_STRUCT_OPS(protect_folio_added, struct folio *folio)
{
	if (!is_folio_relevant(folio))
		return;

	int ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	if (ret != 0)
		bpf_printk("cache_ext: Failed to add folio to sampling_list\n");
}

void BPF_STRUCT_OPS(protect_folio_accessed, struct folio *folio)
{
	if (!is_folio_relevant(folio))
		return;
	track_folio_access(folio);
}

// Eviction mutates NO feature state either: a page's access history persists
// across evictions (re-inserted pages keep their deltas/frequency), matching
// the full-history view training has of the access log. Long-idle entries are
// forgotten naturally by per_folio_map's LRU eviction.
void BPF_STRUCT_OPS(protect_folio_evicted, struct folio *folio)
{
}

// The iterate callback cannot see the eviction ctx, so the "stop once we have
// enough victims" quota lives in these globals, reset at the top of each
// protect_evict_folios call. The kernel serializes the iteration itself under
// the registry write-lock; a concurrent reclaimer racing on the reset can at
// worst end a scan a few folios early or late, which reclaim tolerates.
static u64 evict_target;
static u64 evict_count;

static inline bool folio_evictable_now(struct folio *folio)
{
	if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
		return false;
	if (folio_test_dirty(folio) || folio_test_writeback(folio))
		return false;
	if (folio_test_locked(folio))
		return false;
	return true;
}

static inline bool model_predicts_reuse(struct folio *folio)
{
	s64 raw = compute_feature_score(folio);

	// Untracked folios have no per_folio_map entry: either never accessed
	// since insertion (state is only created at folio_accessed -- typically
	// readahead overshoot) or long-idle and forgotten via LRU map overflow.
	// Both are prime eviction candidates; the model only ever scores pages
	// with real access history.
	if (raw == S64_MAX)
		return false;

	u32 zero = 0;
	struct model_meta *meta = bpf_map_lookup_elem(&model_meta_map, &zero);
	s64 bias = meta ? meta->bias : 0;
	s64 threshold = meta ? meta->threshold : 0;
	return raw + bias > threshold;
}

// Pass 1: head-first scan. Predicted-reused folios are SKIPped (rotated to
// the tail by skip_mode); everything else evictable is evicted until the
// quota is met. Unevictable folios CONTINUE (also rotated -- they get a full
// list trip, same as the old sampler's put-back-at-tail).
static int protect_iter_fn(int idx, struct cache_ext_list_node *node)
{
	if (evict_count >= evict_target)
		return CACHE_EXT_STOP_ITER;
	if (!node || !node->folio)
		return CACHE_EXT_CONTINUE_ITER;
	if (!folio_evictable_now(node->folio))
		return CACHE_EXT_CONTINUE_ITER;
	if (model_predicts_reuse(node->folio))
		return CACHE_EXT_SKIP_NODE;

	evict_count++;
	return CACHE_EXT_EVICT_NODE;
}

// Pass 2 (forward progress): evict head-first, ignoring the model. Only runs
// when pass 1 ran out of scan budget before filling the quota (nearly every
// candidate predicted-reused or unevictable).
static int protect_fallback_iter_fn(int idx, struct cache_ext_list_node *node)
{
	if (evict_count >= evict_target)
		return CACHE_EXT_STOP_ITER;
	if (!node || !node->folio)
		return CACHE_EXT_CONTINUE_ITER;
	if (!folio_evictable_now(node->folio))
		return CACHE_EXT_CONTINUE_ITER;

	evict_count++;
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(protect_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	u64 start_time = bpf_ktime_get_ns();
	dbg_printk("cache_ext: protect_evict_folios\n");

	evict_target = eviction_ctx->request_nr_folios_to_evict;
	evict_count = 0;

	// Everything scanned moves to the tail: victims (their list nodes are
	// freed by the kernel on actual removal), protected folios (the skip
	// rotation), and unevictable folios alike -- a CLOCK-style rotation.
	struct cache_ext_iterate_opts opts = {
		.continue_list = CACHE_EXT_ITERATE_SELF,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
		.skip_list = CACHE_EXT_ITERATE_SELF,
		.skip_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, sampling_list,
						protect_iter_fn, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: protect: failed to iterate list\n");
		return;
	}

	if (eviction_ctx->nr_folios_to_evict <
	    eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, sampling_list,
							protect_fallback_iter_fn,
							&opts, eviction_ctx) < 0)
			bpf_printk("cache_ext: protect: fallback iterate failed\n");
	}

	u64 end_time = bpf_ktime_get_ns();
	dbg_printk("cache_ext: Evicted %lu/%lu pages in %llu ns\n",
		   eviction_ctx->nr_folios_to_evict,
		   eviction_ctx->request_nr_folios_to_evict,
		   end_time - start_time);
	dbg_printk("cache_ext: protected %llu folios this scan\n",
		   opts.nr_folios_skip);
}

SEC(".struct_ops.link")
struct cache_ext_ops protect_ops = {
	.init = (void *)protect_init,
	.evict_folios = (void *)protect_evict_folios,
	.folio_accessed = (void *)protect_folio_accessed,
	.folio_evicted = (void *)protect_folio_evicted,
	.folio_added = (void *)protect_folio_added,
};

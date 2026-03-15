#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define INT64_MAX (9223372036854775807LL)
#define UNKNOWN_DELTA_NS 0xffffffffffffffffULL
#define UNKNOWN_OFFSET_DELTA 0xffffffffU

#define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

//////////
// Maps //
//////////

// Single FIFO list for all pages
__u64 sampling_list;

// Per-folio tracking structures
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

// Per-folio map: key is dev ino index for tracking across eviction
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1000000);
	__type(key, struct tracer_page_key);
	__type(value, struct tracer_page_state);
} per_folio_map SEC(".maps");

// Per-file map for sequential tracking
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 50000);
	__type(key, struct file_key);
	__type(value, struct file_state);
} per_file_map SEC(".maps");

///////////////////
// Model Loading //
///////////////////

#define NUM_MODEL_FEATURES 8
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

////////////
// Logger //
////////////

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} rb_access SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} rb_insertion SEC(".maps");

struct cache_access_fields {
	__u64 timestamp;
	__u64 page_time_delta;
	__u64 page_time_delta2;
	__u64 inode_time_delta;
	__u64 inode_time_delta2;
	__u32 major;
	__u32 minor;
	__u64 ino;
	__u64 offset;
	__u32 seq_distance;
	__u64 file_size;
	__u32 frequency;
	__u32 inode_hotness_ema;
};

struct cache_insertion_event {
	__u64 timestamp;
	__u32 major;
	__u32 minor;
	__u64 ino;
	__u64 index;
};

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

int send_access_log(struct cache_access_fields *fields) {
	struct cache_access_fields *res_ptr = bpf_ringbuf_reserve(&rb_access, sizeof(*fields), 0);
	if (res_ptr == NULL)
		return -1;
	*res_ptr = *fields;
	bpf_ringbuf_submit(res_ptr, 0);
	return 0;
}

int send_insertion_log(struct cache_insertion_event *event) {
	struct cache_insertion_event *res_ptr = bpf_ringbuf_reserve(&rb_insertion, sizeof(*event), 0);
	if (res_ptr == NULL)
		return -1;
	*res_ptr = *event;
	bpf_ringbuf_submit(res_ptr, 0);
	return 0;
}

////////////
// Tracer //
////////////

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
	u64 page_time_delta2 = UNKNOWN_DELTA_NS;
	bool has_page_delta = false;
	if (page_state) {
		if (timestamp >= page_state->last_access_time)
			page_time_delta = timestamp - page_state->last_access_time;
		if (page_state->prev_access_time && timestamp >= page_state->prev_access_time)
			page_time_delta2 = timestamp - page_state->prev_access_time;
		has_page_delta = page_state->last_access_delta != UNKNOWN_DELTA_NS;
	}

	u64 inode_time_delta = UNKNOWN_DELTA_NS;
	u64 inode_time_delta2 = UNKNOWN_DELTA_NS;
	bool has_inode_delta = false;
	if (file_state) {
		if (timestamp >= file_state->last_access_time)
			inode_time_delta = timestamp - file_state->last_access_time;
		if (file_state->prev_access_time && timestamp >= file_state->prev_access_time)
			inode_time_delta2 = timestamp - file_state->prev_access_time;
		has_inode_delta = file_state->last_access_delta != UNKNOWN_DELTA_NS;
	}

	u32 seq_distance = UNKNOWN_OFFSET_DELTA;
	u32 last_offset = UNKNOWN_OFFSET_DELTA;
	if (file_state) {
		u64 offset_diff = index > file_state->last_index ?
			index - file_state->last_index :
			file_state->last_index - index;
		if (offset_diff > UNKNOWN_OFFSET_DELTA) {
			seq_distance = UNKNOWN_OFFSET_DELTA;
			last_offset = UNKNOWN_OFFSET_DELTA;
		} else {
			seq_distance = (u32)offset_diff;
			last_offset = (u32)offset_diff;
		}
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

	int ret = bpf_map_update_elem(&per_folio_map, &folio_key, &new_page_state, BPF_ANY);
	if (ret < 0)
		bpf_printk("per_folio_map write failed: %d", ret);

	struct file_state new_file_state = {
		.last_index = index,
		.last_offset = last_offset,
		.prev_access_time = file_state ? file_state->last_access_time : 0,
		.last_access_time = timestamp,
		.last_access_delta = file_state ? inode_time_delta : UNKNOWN_DELTA_NS,
		.prev_access_delta = file_state ? file_state->last_access_delta : UNKNOWN_DELTA_NS,
		.hotness_ema = inode_hotness_ema,
	};
	ret = bpf_map_update_elem(&per_file_map, &fkey, &new_file_state, BPF_ANY);
	if (ret < 0)
		bpf_printk("per_file_map write failed: %d", ret);

	struct cache_access_fields fields = {
		.timestamp = timestamp,
		.page_time_delta = page_time_delta,
		.page_time_delta2 = page_time_delta2,
		.inode_time_delta = inode_time_delta,
		.inode_time_delta2 = inode_time_delta2,
		.major = (s_dev >> 20),
		.minor = (s_dev & ((1U << 20) - 1)),
		.ino = i_ino,
		.offset = index,
		.seq_distance = seq_distance,
		.file_size = file_size,
		.frequency = frequency,
		.inode_hotness_ema = inode_hotness_ema,
	};
	send_access_log(&fields);
}

static inline void track_folio_insertion(struct folio *folio) {
	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
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

	u64 file_size = get_folio_file_size(folio);

	struct tracer_page_state new_page_state;
	if (page_state) {
		new_page_state.first_access_time = page_state->first_access_time;
		new_page_state.prev_access_time = page_state->last_access_time;
		new_page_state.frequency = page_state->frequency;
		new_page_state.file_size = page_state->file_size;
		new_page_state.last_access_delta = page_state->last_access_delta;
		new_page_state.prev_access_delta = page_state->prev_access_delta;
	} else {
		new_page_state.first_access_time = timestamp;
		new_page_state.prev_access_time = 0;
		new_page_state.frequency = 0;
		new_page_state.file_size = file_size;
		new_page_state.last_access_delta = UNKNOWN_DELTA_NS;
		new_page_state.prev_access_delta = UNKNOWN_DELTA_NS;
	}
	new_page_state.last_access_time = timestamp;
	new_page_state.last_file_offset = index;

	int ret = bpf_map_update_elem(&per_folio_map, &folio_key, &new_page_state, BPF_ANY);
	if (ret < 0)
		bpf_printk("per_folio_map write failed: %d", ret);

	struct file_state new_file_state = {
		.last_index = index,
		.last_offset = file_state ? file_state->last_offset : UNKNOWN_OFFSET_DELTA,
		.prev_access_time = file_state ? file_state->last_access_time : 0,
		.last_access_time = timestamp,
		.last_access_delta = file_state ? file_state->last_access_delta : UNKNOWN_DELTA_NS,
		.prev_access_delta = file_state ? file_state->prev_access_delta : UNKNOWN_DELTA_NS,
		.hotness_ema = file_state ? file_state->hotness_ema : 0,
	};
	ret = bpf_map_update_elem(&per_file_map, &fkey, &new_file_state, BPF_ANY);
	if (ret < 0)
		bpf_printk("per_file_map write failed: %d", ret);

	struct cache_insertion_event event = {
		.timestamp = timestamp,
		.major = (s_dev >> 20),
		.minor = (s_dev & ((1U << 20) - 1)),
		.ino = i_ino,
		.index = index,
	};
	send_insertion_log(&event);
}

///////////////////
// ML Functions  //
///////////////////

// Discretize a feature value using bin edges
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

// Extract features for a folio and compute ML score
static inline s64 compute_ml_score(struct folio *folio) {
	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 index = folio->index;

	if (s_dev == 0 || i_ino == 0) {
		dbg_printk("failed to extract features");
		return S64_MAX;
	}

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

	if (!page_state) {
		dbg_printk("failed to lookup page state");
		return S64_MAX;
	}
	if (!file_state) {
		dbg_printk("failed to lookup file state");
		return S64_MAX;
	}

	bpf_printk("page last access: %llu", page_state->last_access_time);
	bpf_printk("file last access: %llu", file_state->last_access_time);

	dbg_printk("page access time at %llu", page_state->last_access_time);
	dbg_printk("file access time at %llu", file_state->last_access_time);

	// Extract raw features
	u64 raw_features[NUM_MODEL_FEATURES];
	raw_features[PD] = page_state->last_access_delta;
	raw_features[SZ] = page_state->file_size;
	raw_features[FQ] = page_state->frequency;
	raw_features[SD] = file_state->last_offset;
	raw_features[PD2] = page_state->prev_access_delta;
	raw_features[ID] = file_state->last_access_delta;
	raw_features[ID2] = file_state->prev_access_delta;
	raw_features[IE] = file_state->hotness_ema;

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

#undef PROCESS_FEATURE

	return score;
}

/////////////////////
// Policy Handlers //
/////////////////////

s32 BPF_STRUCT_OPS_SLEEPABLE(mglru_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: mglru_ml_init\n");
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: mglru_ml initialized\n");
	return 0;
}

void BPF_STRUCT_OPS(mglru_folio_added, struct folio *folio)
{
	if (!is_folio_relevant(folio))
		return;

	track_folio_insertion(folio);

	int ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(mglru_folio_accessed, struct folio *folio)
{
	if (!is_folio_relevant(folio))
		return;
	track_folio_access(folio);
}

void BPF_STRUCT_OPS(mglru_folio_evicted, struct folio *folio)
{
	if (!is_folio_relevant(folio))
		return;

	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 index = folio->index;

	if (s_dev == 0 || i_ino == 0)
		return;

	struct tracer_page_key folio_key;
	__builtin_memset(&folio_key, 0, sizeof(folio_key));
	folio_key.dev = s_dev;
	folio_key.ino = i_ino;
	folio_key.offset = index;

	bpf_map_delete_elem(&per_folio_map, &folio_key);
}

// Custom sampling function that uses ML scoring
static s64 ml_score_fn(struct cache_ext_list_node *node)
{
	if (!node || !node->folio)
		return S64_MAX;

	// Skip pages that can't be evicted
	if (!folio_test_uptodate(node->folio) || !folio_test_lru(node->folio))
		return S64_MAX;
	if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
		return S64_MAX;
	if (folio_test_locked(node->folio))
		return S64_MAX;

	return compute_ml_score(node->folio);
}

void BPF_STRUCT_OPS(mglru_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	u64 start_time = bpf_ktime_get_ns();
	dbg_printk("cache_ext: mglru_ml_evict_folios\n");

	// Oversample by 5x to get better candidates
	struct sampling_options sampling_opts = {
		.sample_size = 5,
	};

	bpf_cache_ext_list_sample(memcg, sampling_list, ml_score_fn,
				  &sampling_opts, eviction_ctx);

	u64 end_time = bpf_ktime_get_ns();
	u64 elapsed_ns = end_time - start_time;

	dbg_printk("cache_ext: Evicted %d/%d pages in %llu ns\n",
		   eviction_ctx->nr_folios_to_evict,
		   eviction_ctx->request_nr_folios_to_evict,
		   elapsed_ns);
}

SEC(".struct_ops.link")
struct cache_ext_ops mglru_ml_ops = {
	.init = (void *)mglru_init,
	.evict_folios = (void *)mglru_evict_folios,
	.folio_accessed = (void *)mglru_folio_accessed,
	.folio_evicted = (void *)mglru_folio_evicted,
	.folio_added = (void *)mglru_folio_added,
};

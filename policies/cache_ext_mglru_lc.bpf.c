#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define INT64_MAX (9223372036854775807LL)

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define atomic_long_read(ptr) __sync_fetch_and_add(ptr, 0)
#define atomic_long_zero(ptr) __sync_fetch_and_and(ptr, 0)
#define atomic_long_store(ptr, val) __sync_lock_test_and_set(ptr, val)

#define DEFINE_MIN_SEQ(lrugen) \
	unsigned long min_seq = READ_ONCE(lrugen->min_seq)
#define DEFINE_MAX_SEQ(lrugen) \
	unsigned long max_seq = READ_ONCE(lrugen->max_seq)

//////////
// Maps //
//////////

#define MAX_NR_FOLIOS 4000000
#define MAX_NR_GHOST_ENTRIES 400000

struct folio_metadata {
	s64 accesses;
	s64 gen;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, MAX_NR_FOLIOS);
} folio_metadata_map SEC(".maps");

//////////////////
// Ghost Enties //
//////////////////

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);
	__uint(max_entries, MAX_NR_GHOST_ENTRIES);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

static inline void insert_ghost_entry_for_folio(struct folio *folio, int tier) {
	struct ghost_entry ghost_key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	u8 ghost_val = (u8) tier;
	if (bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY))
			bpf_printk("cache_ext: evicted: Failed to add to ghost_map\n");
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline int folio_in_ghost(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	u8 *tier;
	tier = bpf_map_lookup_elem(&ghost_map, &key);
	if (tier == NULL) {
		return -1;
	}
	// TODO: handle non-ENOENT errors
	bpf_map_delete_elem(&ghost_map, &key);
	return (int)(*tier);
}

////////////////////////////////////////////////////////////////////////////////////
//  _  _______ ____  _   _ _____ _       ___ __  __ ____   ___  ____ _____ ____   //
// | |/ / ____|  _ \| \ | | ____| |     |_ _|  \/  |  _ \ / _ \|  _ \_   _/ ___|  //
// | ' /|  _| | |_) |  \| |  _| | |      | || |\/| | |_) | | | | |_) || | \___ \  //
// | . \| |___|  _ <| |\  | |___| |___   | || |  | |  __/| |_| |  _ < | |  ___) | //
// |_|\_\_____|_| \_\_| \_|_____|_____| |___|_|  |_|_|    \___/|_| \_\|_| |____/  //
////////////////////////////////////////////////////////////////////////////////////

// Constants

#define MAX_NR_TIERS 4
#define MIN_NR_GENS 2
#define MAX_NR_GENS 4
#define NR_HIST_GENS 1
#define MIN_LRU_BATCH 64

// Global policy metadata
struct mglru_global_metadata {
	struct bpf_spin_lock lock;
	unsigned long max_seq;
	unsigned long min_seq;
	s64 evicted[MAX_NR_TIERS];
	s64 refaulted[MAX_NR_TIERS];
	s64 tier_selected[MAX_NR_TIERS];
	s64 success_evicted;
	s64 failed_evicted;
	unsigned long avg_refaulted[MAX_NR_TIERS];
	unsigned long avg_total[MAX_NR_TIERS];
	unsigned long protected[MAX_NR_TIERS - 1];
	long nr_pages[MAX_NR_GENS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct mglru_global_metadata);
	__uint(max_entries, 1);
} mglru_global_metadata_map SEC(".maps");

#define DEFINE_LRUGEN_void                                                     \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return;                                                        \
	}

#define DEFINE_LRUGEN_int                                                      \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return -1;                                                     \
	}

#define DEFINE_LRUGEN_bool                                                     \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return false;                                                  \
	}

// TODO: Hook these up with the eventual policy
// Helpers to update metadata

#define assert_valid_tier_0(tier_idx)                                 \
	if (tier_idx < 0 || tier_idx >= MAX_NR_TIERS) {               \
		bpf_printk("cache_ext: Invalid tier index %d\n", \
			   tier_idx);                                 \
		return;                                               \
	}

#define assert_valid_gen_0(gen_idx)                                            \
	if (gen_idx < 0 || gen_idx >= MAX_NR_GENS) {                           \
		bpf_printk("cache_ext: Invalid gen index %d\n", gen_idx); \
		return;                                                        \
	}

#define assert_valid_tier_1(tier_idx)                                 \
	if (tier_idx < 0 || tier_idx >= MAX_NR_TIERS) {               \
		bpf_printk("cache_ext: Invalid tier index %d\n", \
			   tier_idx);                                 \
		return -1;                                            \
	}

#define assert_valid_gen_1(gen_idx)                                            \
	if (gen_idx < 0 || gen_idx >= MAX_NR_GENS) {                           \
		bpf_printk("cache_ext: Invalid gen index %d\n", gen_idx); \
		return -1;                                                     \
	}

inline void update_refaulted_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			   s64 delta)
{
	assert_valid_tier_0(tier_idx);
	__sync_fetch_and_add(&lrugen->refaulted[tier_idx], delta);
}

inline void update_evicted_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			 s64 delta)
{
	assert_valid_tier_0(tier_idx);
	__sync_fetch_and_add(&lrugen->evicted[tier_idx], delta);
}

inline void update_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx,
			  s64 delta)
{
	assert_valid_gen_0(gen_idx);
	__sync_fetch_and_add(&lrugen->nr_pages[gen_idx], delta);
}

inline void update_tier_selected_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			  s64 delta)
{
	assert_valid_tier_0(tier_idx);
	__sync_fetch_and_add(&lrugen->tier_selected[tier_idx], delta);
}


inline s64 read_refaulted_stat(struct mglru_global_metadata *lrugen, int tier_idx)
{
	assert_valid_tier_1(tier_idx);
	return max(0, atomic_long_read(&lrugen->refaulted[tier_idx]));
}

inline s64 read_evicted_stat(struct mglru_global_metadata *lrugen, int tier_idx)
{
	assert_valid_tier_1(tier_idx);
	return max(0, atomic_long_read(&lrugen->evicted[tier_idx]));
}

inline s64 read_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx)
{
	assert_valid_gen_1(gen_idx);
	return max(0, atomic_long_read(&lrugen->nr_pages[gen_idx]));
}

// Invoke when promoting a folio in the eviction iteration
// See: https://github.com/cache-ext/linux-cachestream/blob/c22ffcac6b53ef4054483070fb902895ef10fd12/mm/vmscan.c#L4941-L4952
inline void update_protected_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			   s64 delta)
{
	__sync_fetch_and_add(&lrugen->protected[tier_idx - 1], delta);
}

// Gen lists
static __u64 mglru_lists[MAX_NR_GENS];

/******************************************************************************
 *                          PID controller
 ******************************************************************************/

/*
 * A feedback loop based on Proportional-Integral-Derivative (PID) controller.
 *
 * The P term is refaulted/(evicted+protected) from a tier in the generation
 * currently being evicted; the I term is the exponential moving average of the
 * P term over the generations previously evicted, using the smoothing factor
 * 1/2; the D term isn't supported.
 *
 * The setpoint (SP) is always the first tier of one type; the process variable
 * (PV) is either any tier of the other type or any other tier of the same
 * type.
 *
 * The error is the difference between the SP and the PV; the correction is to
 * turn off protection when SP>PV or turn on protection when SP<PV.
 *
 * For future optimizations:
 * 1. The D term may discount the other two terms over time so that long-lived
 *    generations can resist stale information.
 */

 // Avoid name conflict with kernel struct ctrl_pos if MGLRU is enabled
 struct ctrl_pos___x {
	unsigned long refaulted;
	unsigned long total;
	int gain;
};

static inline void read_ctrl_pos(struct mglru_global_metadata *lrugen, int tier,
			  int gain, struct ctrl_pos___x *pos)
{
	pos->refaulted = lrugen->avg_refaulted[tier] +
			 __sync_fetch_and_add(&lrugen->refaulted[tier], 0);
	pos->total = lrugen->avg_total[tier] +
		     __sync_fetch_and_add(&lrugen->evicted[tier], 0);
	if (tier)
		pos->total += lrugen->protected[tier - 1];
	pos->gain = gain;
}

// Needs the LRU lock. Why???
static inline void reset_ctrl_pos(struct mglru_global_metadata *lrugen, bool carryover)
{
	int tier;
	bool clear = carryover ? NR_HIST_GENS == 1 : NR_HIST_GENS > 1;

	// lockdep_assert_held(&lruvec->lru_lock);

	if (!carryover && !clear)
		return;

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		if (carryover) {
			unsigned long sum;

			sum = lrugen->avg_refaulted[tier] +
			      atomic_long_read(&lrugen->refaulted[tier]);
			WRITE_ONCE(lrugen->avg_refaulted[tier], sum / 2);

			sum = lrugen->avg_total[tier] +
			      atomic_long_read(&lrugen->evicted[tier]);
			if (tier)
				sum += lrugen->protected[tier - 1];
			WRITE_ONCE(lrugen->avg_total[tier], sum / 2);
		}

		if (clear) {
			atomic_long_zero(&lrugen->refaulted[tier]);
			atomic_long_zero(&lrugen->evicted[tier]);
			if (tier)
				WRITE_ONCE(lrugen->protected[tier - 1], 0);
		}
	}
}

static inline bool positive_ctrl_err(struct ctrl_pos___x *sp, struct ctrl_pos___x *pv)
{
	/*
	 * Return true if the PV has a limited number of refaults or a lower
	 * refaulted/total than the SP.
	 */
	return pv->refaulted < MIN_LRU_BATCH ||
	       pv->refaulted * (sp->total + MIN_LRU_BATCH) * sp->gain <=
		       (sp->refaulted + 1) * pv->total * pv->gain;
}

///////////////////////////////////////
// Utils that use the PID controller //
///////////////////////////////////////

static inline int get_tier_idx(struct mglru_global_metadata *lrugen)
{
	int tier;
	struct ctrl_pos___x sp, pv;

	/*
	 * To leave a margin for fluctuations, use a larger gain factor (1:2).
	 * This value is chosen because any other tier would have at least twice
	 * as many refaults as the firsfirst tier.
	 */
	read_ctrl_pos(lrugen, 0, 1, &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lrugen, tier, 2, &pv);
		if (!positive_ctrl_err(&sp, &pv))
			break;
	}

	return tier - 1;
}

// static inline int get_tier_idx(struct mglru_global_metadata *lrugen)
// {
// 	// TODO: Swap this with the real implementation once we add refault tracking
// 	// support.
// 	return 0;
// }

static inline void folio_inc_refs(struct folio *folio)
{
	struct folio_metadata *metadata;
	__u64 key = (__u64)folio;

	metadata = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!metadata) {
		bpf_printk(
			"cache_ext: Tried to inc refs but folio not found in map.\n");
		return;
	}
	__sync_fetch_and_add(&metadata->accesses, 1);
}

static inline int folio_lru_refs(struct folio *folio)
{
	struct folio_metadata *metadata;
	__u64 key = (__u64)folio;

	metadata = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!metadata)
		return -1;

	return atomic_long_read(&metadata->accesses);
}

static inline unsigned int lru_gen_from_seq(unsigned long seq)
{
	return seq % MAX_NR_GENS;
}

static inline bool folio_test_active(struct folio *folio)
{
	return folio_lru_refs(folio) >= 2;
}

// Only counts up to 3.
static inline int order_base_2(int n)
{
	if (n <= 1) {
		return 0;
	} else if (n <= 3) {
		return 1;
	} else if (n <= 7) {
		return 2;
	} else if (n <= 8) {
		return 3;
	}
	return 3;
}

static inline int lru_tier_from_refs(int refs)
{
	/* see the comment in folio_lru_refs() */
	// kernel does some off-by-one calculation here, we remove the +1
	// return order_base_2(refs + 1);
	return order_base_2(refs);
}

static inline bool gen_within_limits(unsigned int gen)
{
	return 0 <= gen && gen <= MAX_NR_GENS;
}

static inline int get_nr_gens(struct mglru_global_metadata *lrugen)
{
	return lrugen->max_seq - lrugen->min_seq + 1;
}

static inline bool gen_almost_empty(struct mglru_global_metadata *lrugen,
				    int min_seq)
{
	int oldest_gen = lru_gen_from_seq(min_seq);
	int nr_folios = read_nr_pages_stat(lrugen, oldest_gen);
	int threshold = 4;
	return nr_folios <= threshold;
}

// TODO: This is supposed to run with a lock.
static inline bool lru_gen_add_folio(struct folio *folio)
{
	unsigned long seq;
	if (folio_test_unevictable(folio)) {
		bpf_printk("cache_ext: Unevictable folio\n");
		return false;
	}

	DEFINE_LRUGEN_bool;
	DEFINE_MIN_SEQ(lrugen);
	DEFINE_MAX_SEQ(lrugen);
	/*
	 * There are four common cases for this page:
	 * 1. If it's hot, i.e., freshly faulted in, add it to the youngest
	 *    generation, and it's protected over the rest below.
	 * 2. If it can't be evicted immediately, i.e., a dirty page pending
	 *    writeback, add it to the second youngest generation.
	 * 3. If it should be evicted first, e.g., cold and clean from
	 *    folio_rotate_reclaimable(), add it to the oldest generation.
	 * 4. Everything else falls between 2 & 3 above and is added to the
	 *    second oldest generation if it's considered inactive, or the
	 *    oldest generation otherwise. See lru_gen_is_active().
	 */
	if (folio_test_active(folio))
		seq = max_seq;
	else if ((folio_test_reclaim(folio) &&
		  (folio_test_dirty(folio) || folio_test_writeback(folio))))
		seq = max_seq - 1;
	else if (min_seq + MIN_NR_GENS >= max_seq)
		seq = min_seq;
	else
		seq = min_seq + 1;

	unsigned int gen = lru_gen_from_seq(seq);
	if (!gen_within_limits(gen)) {
		bpf_printk(
			"cache_ext: Invalid gen %d (min_seq=%lu, max_seq=%lu)\n",
			gen, min_seq, max_seq);
		return false;
	}

	// Update policy metadata
	struct folio_metadata metadata = { .accesses = 1, .gen = gen };
	__u64 key = (__u64)folio;
	int ret = bpf_map_update_elem(&folio_metadata_map, &key, &metadata,
				      BPF_ANY);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to save folio metadata\n");
		return false;
	}
	update_nr_pages_stat(lrugen, gen, folio_nr_pages(folio));

	// Update refaulted stats
	ret = folio_in_ghost(folio);
	if (ret >= 0) {
		int tier = ret;
		update_refaulted_stat(lrugen, tier, 1);
	}

	// lru_gen_update_size(lruvec, folio, -1, gen);
	ret = bpf_cache_ext_list_add(mglru_lists[gen], folio);
	if (ret != 0) {
		bpf_printk(
			"cache_ext: Failed to add folio to mglru_lists[%d]\n",
			gen);
		return false;
	}

	return true;
}

static inline bool should_run_aging(struct mglru_global_metadata *lrugen,
				    unsigned long max_seq)
{
	unsigned int gen;
	unsigned long old = 0;
	unsigned long young = 0;
	unsigned long total = 0;
	DEFINE_MIN_SEQ(lrugen);

	/* whether this lruvec is completely out of cold folios */
	if (min_seq + MIN_NR_GENS > max_seq) {
		return true;
	}

	unsigned long seq;
	int max_iter =  min(MAX_NR_GENS, max_seq - min_seq);
	for (int i = 0; i < max_iter; i++) {
		seq = min_seq + i;
		unsigned long size = 0;

		gen = lru_gen_from_seq(seq);

		size += max(read_nr_pages_stat(lrugen, gen), 0L);

		total += size;
		if (seq == max_seq)
			young += size;
		else if (seq + MIN_NR_GENS == max_seq)
			old += size;
	}

	/*
	 * The aging tries to be lazy to reduce the overhead, while the eviction
	 * stalls when the number of generations reaches MIN_NR_GENS. Hence, the
	 * ideal number of generations is MIN_NR_GENS+1.
	 */
	if (min_seq + MIN_NR_GENS < max_seq)
		return false;

	/*
	 * It's also ideal to spread pages out evenly, i.e., 1/(MIN_NR_GENS+1)
	 * of the total number of pages for each generation. A reasonable range
	 * for this average portion is [1/MIN_NR_GENS, 1/(MIN_NR_GENS+2)]. The
	 * aging cares about the upper bound of hot pages, while the eviction
	 * cares about the lower bound of cold pages.
	 */
	if (young * MIN_NR_GENS > total)
		return true;
	if (old * (MIN_NR_GENS + 2) < total)
		return true;

	return false;
}

static inline bool try_to_inc_min_seq(struct mglru_global_metadata *lrugen)
{
	// TODO: Check if the min_seq list is empty and if it is, increase min_seq.
	DEFINE_MIN_SEQ(lrugen);
	if (!gen_almost_empty(lrugen, min_seq)) {
		return false;
	}
	WRITE_ONCE(lrugen->min_seq, lrugen->min_seq + 1);
	reset_ctrl_pos(lrugen, true);
	return true;
}

static inline bool try_to_inc_max_seq(struct mglru_global_metadata *lrugen)
{
	// int prev, next;
	// spin_lock_irq(&lruvec->lru_lock);

	if (get_nr_gens(lrugen) == MAX_NR_GENS) {
		// Try to increase min_seq
		int ret = try_to_inc_min_seq(lrugen);
		if (!ret) {
			return false;
		}
	}
	// spin_unlock_irq(&lruvec->lru_lock);

	// TODO: Do we need this?
	/*
	 * Update the active/inactive LRU sizes for compatibility. Both sides of
	 * the current max_seq need to be covered, since max_seq+1 can overlap
	 * with min_seq[LRU_GEN_ANON] if swapping is constrained. And if they do
	 * overlap, cold/hot inversion happens.
	 */
	// prev = lru_gen_from_seq(lrugen->max_seq - 1);
	// next = lru_gen_from_seq(lrugen->max_seq + 1);

	// for (type = 0; type < ANON_AND_FILE; type++) {
	// 	for (zone = 0; zone < MAX_NR_ZONES; zone++) {
	// 		enum lru_list lru = type * LRU_INACTIVE_FILE;
	// 		long delta = lrugen->nr_pages[prev] -
	// 			     lrugen->nr_pages[next];

	// 		if (!delta)
	// 			continue;

	// 		__update_lru_size(lruvec, lru, zone, delta);
	// 		__update_lru_size(lruvec, lru + LRU_ACTIVE, zone, -delta);
	// 	}
	// }

	reset_ctrl_pos(lrugen, false);

	// We don't use the timestamp metadata for our MGLRU
	/* make sure preceding modifications appear */
	WRITE_ONCE(lrugen->max_seq, lrugen->max_seq + 1);
	return true;

	// spin_unlock_irq(&lruvec->lru_lock);
}

////////////////////////////////////////////////////////////
//   ____    _    ____ _   _ _____     _______  _______   //
//  / ___|  / \  / ___| | | | ____|   | ____\ \/ /_   _|  //
// | |     / _ \| |   | |_| |  _|     |  _|  \  /  | |    //
// | |___ / ___ \ |___|  _  | |___    | |___ /  \  | |    //
//  \____/_/   \_\____|_| |_|_____|___|_____/_/\_\ |_|    //
//                               |_____|                  //
////////////////////////////////////////////////////////////


////////////
// Policy //
////////////


struct eviction_metadata {
	__u64 curr_gen;
	__u64 next_gen;
	__u64 iter_reached;
	__u64 tier_threshold;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct eviction_metadata);
} mglru_percpu_array SEC(".maps");

struct tracer_page_key {
	__u32 dev;
	__u64 ino;
	__u64 offset;
};

// Per-folio tracking structures (ported from Rust tracers)
struct tracer_page_state {
	__u64 first_access_time;
	__u64 prev_access_time;
	__u64 last_access_time;
	__u64 last_file_offset;
	__u64 file_size;
	__u32 frequency;
};

struct file_key {
	__u32 dev;
	__u64 ino;
};

struct file_state {
	__u64 last_offset;
	__u64 prev_access_time;
	__u64 last_access_time;
	__u32 hotness_ema;
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


struct eviction_metadata * get_eviction_metadata() {
	u32 key = 0;
	return bpf_map_lookup_elem(&mglru_percpu_array, &key);
}

void set_eviction_metadata(struct eviction_metadata *eviction_meta) {
	u32 key = 0;
	int ret = bpf_map_update_elem(&mglru_percpu_array, &key, eviction_meta, BPF_ANY);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to update eviction metadata\n");
	}
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		return false;
	}
	if (folio->mapping == NULL) {
		return false;
	}
	if (folio->mapping->host == NULL) {
		return false;
	}
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	return res;
}

////////////
// tracer //
////////////



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
    __u64 timestamp;        // ts: bpf_ktime_get_ns()
    __u64 page_time_delta;  // pd: delta since last page access (ns)
    __u64 page_time_delta2; // p2: delta since last two page access (ns)
    __u64 inode_time_delta; // id: delta since last inode access (ns)
    __u64 inode_time_delta2;// i2: delta since last two inode access (ns)
    __u32 major;            // dm: device major
    __u32 minor;            // dn: device minor
    __u64 ino;              // in: inode number (i_ino)
    __u64 offset;           // of: page index (folio index)
    __u32 seq_distance;     // sd: pages away from last inode offset
    __u64 file_size;        // sz: file size
    __u32 frequency;        // fq: frequency
    __u32 inode_hotness_ema;// ie: inode hotness EMA
};

struct cache_insertion_event {
    __u64 timestamp;   /* t: bpf_ktime_get_ns() */
    __u32 major;       /* d: device major */
    __u32 minor;       /* d: device minor */
    __u64 ino;         /* i: inode number (data.i_ino) */
    __u64 index;       /* x: page index (data.index) */
};

int send_access_log(struct cache_access_fields *fields) {
    struct cache_access_fields *res_ptr = bpf_ringbuf_reserve(&rb_access, sizeof(*fields), 0);
    if (res_ptr == NULL) {
        return -1;
    }

    *res_ptr = *fields;
    bpf_ringbuf_submit(res_ptr, 0);
    return 0;
}

int send_insertion_log(struct cache_insertion_event *event) {
    struct cache_insertion_event *res_ptr = bpf_ringbuf_reserve(&rb_insertion, sizeof(*event), 0);
    if (res_ptr == NULL) {
        return -1;
    }

    *res_ptr = *event;
    bpf_ringbuf_submit(res_ptr, 0);
    return 0;
}

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

static inline void track_folio_access(struct folio *folio) {
	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 file_size = get_folio_file_size(folio);
   	u64 index = folio->index;
    u64 timestamp = bpf_ktime_get_ns();

	struct tracer_page_key folio_key = {
        .dev = s_dev,
        .ino = i_ino,
        .offset = index
    };

	if (s_dev == 0 || i_ino == 0) {
		return;
	}

	struct file_key fkey = {
		.dev = s_dev,
		.ino = i_ino,
	};

	struct tracer_page_state *page_state = bpf_map_lookup_elem(&per_folio_map, &folio_key);
	struct file_state *file_state = bpf_map_lookup_elem(&per_file_map, &fkey);

	u64 page_time_delta = 0xffffffffffffffffULL;
	u64 page_time_delta2 = 0xffffffffffffffffULL;
	bool has_page_delta = false;
	bool has_page_delta2 = false;
	if (page_state) {
		if (timestamp >= page_state->last_access_time) {
			page_time_delta = timestamp - page_state->last_access_time;
			has_page_delta = true;
		}
		if (page_state->prev_access_time &&
		    timestamp >= page_state->prev_access_time) {
			page_time_delta2 = timestamp - page_state->prev_access_time;
			has_page_delta2 = true;
		}
	}

	u64 inode_time_delta = 0xffffffffffffffffULL;
	u64 inode_time_delta2 = 0xffffffffffffffffULL;
	bool has_inode_delta = false;
	bool has_inode_delta2 = false;
	if (file_state) {
		if (timestamp >= file_state->last_access_time) {
			inode_time_delta = timestamp - file_state->last_access_time;
			has_inode_delta = true;
		}
		if (file_state->prev_access_time &&
		    timestamp >= file_state->prev_access_time) {
			inode_time_delta2 = timestamp - file_state->prev_access_time;
			has_inode_delta2 = true;
		}
	}

	u32 seq_distance = 0;
	if (file_state) {
		u64 offset_diff = index > file_state->last_offset ?
			index - file_state->last_offset :
			file_state->last_offset - index;
		if (offset_diff > 0xffffffffU) {
			seq_distance = 0xffffffffU;
		} else {
			seq_distance = (u32)offset_diff;
		}
	}

	u32 inode_hotness_ema = 1000;
	if (file_state) {
		u64 half_life_ns = 1000000000ULL; // 1 second
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
				if (half_lives > 10) {
					decay = 0;
				} else {
					decay = 1000 >> half_lives;
				}
			}
			u64 decayed = ((u64)file_state->hotness_ema * decay) / 1000;
			inode_hotness_ema = (u32)(decayed + 1000);
		}
	}

	u32 frequency = 1000;
	if (page_state) {
		if (has_page_delta && page_time_delta > 0) {
			u64 half_life_ns = 1000000000ULL; // 1 second
			u64 decay;
			if (page_time_delta < half_life_ns) {
				u64 ratio = (page_time_delta * 1000) / half_life_ns;
				decay = 1000 - (ratio / 2);
			} else {
				u64 half_lives = page_time_delta / half_life_ns;
				if (half_lives > 10) {
					decay = 0;
				} else {
					decay = 1000 >> half_lives;
				}
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
	} else {
		new_page_state.first_access_time = timestamp;
		new_page_state.prev_access_time = 0;
	}
	new_page_state.last_access_time = timestamp;
	new_page_state.last_file_offset = index;
	new_page_state.file_size = file_size;
	new_page_state.frequency = frequency;

	bpf_map_update_elem(&per_folio_map, &folio_key, &new_page_state, BPF_ANY);

	struct file_state new_file_state = {
		.last_offset = index,
		.prev_access_time = file_state ? file_state->last_access_time : 0,
		.last_access_time = timestamp,
		.hotness_ema = inode_hotness_ema,
	};
	bpf_map_update_elem(&per_file_map, &fkey, &new_file_state, BPF_ANY);

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

// track folio insertion
static inline void track_folio_insertion(struct folio *folio) {
   	u32 s_dev = get_folio_dev(folio);
	u64 i_ino = get_folio_ino(folio);
	u64 index = folio->index;
    u64 timestamp = bpf_ktime_get_ns();

    struct tracer_page_key folio_key = {
        .dev = s_dev,
        .ino = i_ino,
        .offset = index
    };

	if (s_dev == 0 || i_ino == 0) {
		return;
	}

	struct file_key fkey = {
		.dev = s_dev,
		.ino = i_ino,
	};

	struct tracer_page_state *page_state = bpf_map_lookup_elem(&per_folio_map, &folio_key);
	struct file_state *file_state = bpf_map_lookup_elem(&per_file_map, &fkey);

	struct tracer_page_state new_page_state;
	if (page_state) {
		new_page_state.first_access_time = page_state->first_access_time;
		new_page_state.prev_access_time = page_state->last_access_time;
		new_page_state.frequency = page_state->frequency;
		new_page_state.file_size = page_state->file_size;
	} else {
		new_page_state.first_access_time = timestamp;
		new_page_state.prev_access_time = 0;
		new_page_state.frequency = 0;
		new_page_state.file_size = 0;
	}
	new_page_state.last_access_time = timestamp;
	new_page_state.last_file_offset = index;

	bpf_map_update_elem(&per_folio_map, &folio_key, &new_page_state, BPF_ANY);

	struct file_state new_file_state = {
		.last_offset = index,
		.prev_access_time = file_state ? file_state->last_access_time : 0,
		.last_access_time = timestamp,
		.hotness_ema = file_state ? file_state->hotness_ema : 0,
	};
	bpf_map_update_elem(&per_file_map, &fkey, &new_file_state, BPF_ANY);

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
// model loading //
///////////////////

#define MODEL_FEATURES 4
#define MAX_BINS 10

enum model_features {
    PD = 0, // delta t
    PD2 = 1,
    FQ = 2, // page hotness
    ID = 3, // delta t for inode
    ID2 = 4,
    IE = 5, // inode hotness
    SZ = 6, // size
    SD = 7, // seq
};

// defines the amount of bins in each model feature
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MODEL_FEATURES);
	__type(key, enum model_features);
	__type(value, __u8); // n bins in each. cannot exceed MAX_BINS
} n_bins_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MODEL_FEATURES);
    __type(key, enum model_features);
    __type(value, __u64[MAX_BINS]); // bin edges, [start, end)
} bin_edges_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MODEL_FEATURES);
    __type(key, enum model_features);
    __type(value, __u64[MAX_BINS]); // bin weights (quantized)
} nn_weights_map SEC(".maps");

s32 BPF_STRUCT_OPS_SLEEPABLE(mglru_init, struct mem_cgroup *memcg)
{
	DEFINE_LRUGEN_int;
	WRITE_ONCE(lrugen->max_seq, MIN_NR_GENS + 1);
	for (int i = 0; i < MAX_NR_GENS; i++) {
		__u64 list_ptr = bpf_cache_ext_ds_registry_new_list(memcg);
		if (list_ptr == 0) {
					bpf_printk(
			"cache_ext: Failed to allocate list for gen %d\n",
			i);
			return -1;
		}
		mglru_lists[i] = list_ptr;
	}
	bpf_printk("cache_ext: mglru initialized");
	return 0;
}


// MGLRU iteration function. Logic is mainly ported from sort_folio.
static int mglru_iter_fn(int idx, struct cache_ext_list_node *a)
{
	// We skip the following cases from sort_folio since we asssume we don't
	// accept these folios in this policy:
	// - Unevictable folios
	// - Swap-backed folios
	// - Promoted folios (these only appear through PTE accesses,
	//                    fd-accessed folios are promoted based on their tier)

	struct mglru_global_metadata *lrugen;
	int key__ = 0;
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);
	if (!lrugen) {
		bpf_printk(
			"cache_ext: Failed to lookup lrugen metadata\n");
		return CACHE_EXT_EVICT_NODE;
	}

	struct eviction_metadata *eviction_meta = get_eviction_metadata();
	if (!eviction_meta) {
		bpf_printk("cache_ext: iter_fn: Failed to get eviction metadata\n");
		return CACHE_EXT_EVICT_NODE;
	}
	eviction_meta->iter_reached = idx;

	// Get folio metadata
	__u64 key = (__u64)a->folio;
	struct folio_metadata *meta =
		bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
		bpf_printk("cache_ext: iter_fn: Failed to get metadata\n");
		// TODO: Maybe we should evict it instead?
		return CACHE_EXT_EVICT_NODE;
	}

	int tier_threshold = eviction_meta->tier_threshold;
	if (tier_threshold > MAX_NR_TIERS || tier_threshold < 0) {
		bpf_printk("cache_ext: Invalid tier threshold %d\n", tier_threshold);
	}
	// int tier_threshold = 2;
	int tier = lru_tier_from_refs(atomic_long_read(&meta->accesses));

	/* protected */
	if (tier > tier_threshold) {
		update_protected_stat(lrugen, tier, folio_nr_pages(a->folio));
		// promote to next gen
		// TODO: Update nr_pages stats
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}

	/* waiting for writeback */
	if (folio_test_locked(a->folio) || folio_test_writeback(a->folio) ||
	    folio_test_dirty(a->folio)) {
		// promote to next gen
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(mglru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	DEFINE_LRUGEN_void;

	bpf_printk("num folios in eviction request: %d", eviction_ctx->request_nr_folios_to_evict);

	bool inc_max_seq_failed = false;
	bpf_spin_lock(&lrugen->lock);
	DEFINE_MIN_SEQ(lrugen);
	DEFINE_MAX_SEQ(lrugen);
	if (should_run_aging(lrugen, max_seq)) {
		if (!try_to_inc_max_seq(lrugen)){
			// Workaround: Not allowed to call bpf_printk under spinlock
			inc_max_seq_failed = true;
		}
	}
	if (max_seq - min_seq > MIN_NR_GENS)
		try_to_inc_min_seq(lrugen);
	// Read min/max seq again
	min_seq = READ_ONCE(lrugen->min_seq);
	max_seq = READ_ONCE(lrugen->max_seq);
	int oldest_gen = lru_gen_from_seq(min_seq);
	volatile unsigned int next_gen = (oldest_gen + 1) % MAX_NR_GENS;
	bpf_spin_unlock(&lrugen->lock);

	if (inc_max_seq_failed) {
		bpf_printk("cache_ext: Failed to increment max_seq\n");
	}

	int tier_threshold = get_tier_idx(lrugen);
	update_tier_selected_stat(lrugen, tier_threshold, 1);

	// Save eviction metadata for stats
	struct eviction_metadata ev_meta = {
		.curr_gen = oldest_gen,
		.next_gen = next_gen,
		.tier_threshold = tier_threshold,
	};
	set_eviction_metadata(&ev_meta);

	assert_valid_gen_0(next_gen);

	__u64 next_gen_list = mglru_lists[next_gen];
	__u64 oldest_gen_list = mglru_lists[oldest_gen];
	struct cache_ext_iterate_opts opts = {
		.continue_list = next_gen_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};


	int ret = bpf_cache_ext_list_iterate_extended(
		memcg, oldest_gen_list, mglru_iter_fn, &opts, eviction_ctx);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to iterate list\n");
		return;
	}
	struct eviction_metadata *eviction_meta = get_eviction_metadata();
	if (eviction_meta == NULL) return;
	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
        bpf_printk("only %d/%d folios, retrying", eviction_ctx->nr_folios_to_evict, eviction_ctx->request_nr_folios_to_evict);
		min_seq = READ_ONCE(lrugen->min_seq);
		oldest_gen = lru_gen_from_seq(min_seq);
		next_gen = (oldest_gen + 1) % MAX_NR_GENS;
		__u64 next_gen_list = mglru_lists[next_gen];
		__u64 oldest_gen_list = mglru_lists[oldest_gen];
		struct cache_ext_iterate_opts opts = {
			.continue_list = next_gen_list,
			.continue_mode = CACHE_EXT_ITERATE_TAIL,
			.evict_list = CACHE_EXT_ITERATE_SELF,
			.evict_mode = CACHE_EXT_ITERATE_TAIL,
		};
		int ret = bpf_cache_ext_list_iterate_extended(
			memcg, oldest_gen_list, mglru_iter_fn, &opts, eviction_ctx);
		if (ret < 0) {
			bpf_printk("cache_ext: Failed to iterate list\n");
			return;
		}
	}
	s64 success_evicted = eviction_ctx->nr_folios_to_evict;
	s64 failed_evicted = max(0, eviction_ctx->request_nr_folios_to_evict - eviction_ctx->nr_folios_to_evict);
	__sync_fetch_and_add(&lrugen->failed_evicted, failed_evicted);
	__sync_fetch_and_add(&lrugen->success_evicted, success_evicted);
	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		bpf_printk("cache_ext: Failed to evict requested number of folios: %d/%d. Used list idx %d, list ptr: %p. Iter reached: %d\n",
				eviction_ctx->nr_folios_to_evict,
				eviction_ctx->request_nr_folios_to_evict,
				oldest_gen,
				oldest_gen_list,
				eviction_meta->iter_reached);
	}
}

void BPF_STRUCT_OPS(mglru_folio_added, struct folio *folio)
{
	if (!is_folio_relevant(folio)) {
		return;
	}
	track_folio_insertion(folio);
	lru_gen_add_folio(folio);
}

void BPF_STRUCT_OPS(mglru_folio_accessed, struct folio *folio)
{
	if (!is_folio_relevant(folio)) {
		return;
	}
	track_folio_access(folio);
	folio_inc_refs(folio);
}

void BPF_STRUCT_OPS(mglru_folio_evicted, struct folio *folio)
{
	if (!is_folio_relevant(folio)) {
		return;
	}
	DEFINE_LRUGEN_void;
	// Remove tracked metadata
	struct folio_metadata *metadata;
	__u64 key = (__u64)folio;

	metadata = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!metadata) {
		bpf_printk(
			"cache_ext: Tried to delete folio metadata but not found in map.\n");
		return;
	}
	// Add ghost entry for refault detection
	int tier = lru_tier_from_refs(atomic_long_read(&metadata->accesses));
	insert_ghost_entry_for_folio(folio, tier);

	// Update generation page count
	update_evicted_stat(lrugen, tier, 1);
	update_nr_pages_stat(lrugen, metadata->gen, -folio_nr_pages(folio));

	bpf_map_delete_elem(&folio_metadata_map, &key);

}

SEC(".struct_ops.link")
struct cache_ext_ops mglru_ops = {
	.init = (void *)mglru_init,
	.evict_folios = (void *)mglru_evict_folios,
	.folio_accessed = (void *)mglru_folio_accessed,
	.folio_evicted = (void *)mglru_folio_evicted,
	.folio_added = (void *)mglru_folio_added,
};

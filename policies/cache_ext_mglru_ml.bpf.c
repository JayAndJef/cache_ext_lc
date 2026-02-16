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

// defines the amount of bins in each model feature
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_MODEL_FEATURES);
	__type(key, __u32);
	__type(value, __u8); // n bins in each. cannot exceed MAX_BINS
} n_bins_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_MODEL_FEATURES);
    __type(key, __u32);
    __type(value, __u64[MAX_BINS]); // bin edges, [start, end)
} bin_edges_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_MODEL_FEATURES);
    __type(key, __u32);
    __type(value, s64[MAX_BINS]); // bin weights (integer, can be negative)
} nn_weights_map SEC(".maps");

// Candidate structure for ML reranking
#define MAX_CANDIDATES 64

struct candidate {
	__u64 folio_addr;   /* raw folio address (scalar), used as key + returned to kernel */
	s64   score;        /* computed while folio ptr is trusted */
	__s32 pages;        /* folio_nr_pages computed while folio ptr is trusted */
	__s32 tier;         /* tier computed while meta ptr is trusted */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct candidate[MAX_CANDIDATES]);
} candidates_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, __u32); // number of candidates collected
} num_candidates_map SEC(".maps");

///////////////////
// ML Functions  //
///////////////////

// Discretize a feature value using bin edges
// bin_edges contains only the INTERIOR edges (n_bins - 1 edges)
// Unrolled version for verifier friendliness
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
		// Cannot extract features, return worst score
		return S64_MAX;
	}

	struct tracer_page_key folio_key = {
		.dev = s_dev,
		.ino = i_ino,
		.offset = index
	};

	struct file_key fkey = {
		.dev = s_dev,
		.ino = i_ino,
	};

	struct tracer_page_state *page_state = bpf_map_lookup_elem(&per_folio_map, &folio_key);
	struct file_state *file_state = bpf_map_lookup_elem(&per_file_map, &fkey);

	if (!page_state || !file_state) {
		return S64_MAX;
	}

	u64 timestamp = bpf_ktime_get_ns();

	// Extract raw features (matching pairwise_ranker.py order: pd, sz, fq, sd, p2, id, i2, ie)
	u64 raw_features[NUM_MODEL_FEATURES];

	// PD: page_time_delta
	raw_features[PD] = (timestamp >= page_state->last_access_time) ?
		(timestamp - page_state->last_access_time) : 0xffffffffffffffffULL;

	// SZ: file_size
	raw_features[SZ] = page_state->file_size;

	// FQ: frequency
	raw_features[FQ] = page_state->frequency;

	// SD: seq_distance
	u64 offset_diff = index > file_state->last_offset ?
		index - file_state->last_offset : file_state->last_offset - index;
	raw_features[SD] = (offset_diff > 0xffffffffU) ? 0xffffffffU : (u32)offset_diff;

	// PD2: page_time_delta2
	raw_features[PD2] = (page_state->prev_access_time && timestamp >= page_state->prev_access_time) ?
		(timestamp - page_state->prev_access_time) : 0xffffffffffffffffULL;

	// ID: inode_time_delta
	raw_features[ID] = (timestamp >= file_state->last_access_time) ?
		(timestamp - file_state->last_access_time) : 0xffffffffffffffffULL;

	// ID2: inode_time_delta2
	raw_features[ID2] = (file_state->prev_access_time && timestamp >= file_state->prev_access_time) ?
		(timestamp - file_state->prev_access_time) : 0xffffffffffffffffULL;

	// IE: inode_hotness_ema
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

// Context for bpf_loop callbacks
struct sort_outer_ctx {
	struct candidate* candidates;
	__u32 n;
	__u32 positions;
};

struct sort_inner_ctx {
	struct candidate* candidates;
	__u32 n;
	__u32 i;
	__u32 *min_idx;
	s64 *min_score;
};

// Inner loop callback: find minimum in range [i+1..n-1]
static int find_min_callback(__u32 index, void *data) {
	struct sort_inner_ctx *ctx = data;
	__u32 j = ctx->i + 1 + index;

	if (j >= ctx->n) return 1; // stop iteration
	if (j >= MAX_CANDIDATES) return 1;

	/// manual assembly bounds check
	asm volatile(
	    "%[j] &= %[mask]"
		: [j] "+r" (j)
		: [mask] "i" (MAX_CANDIDATES - 1)
	);

	if (ctx->candidates[j].score < *ctx->min_score) {
		*ctx->min_idx = j;
		*ctx->min_score = ctx->candidates[j].score;
	}

	return 0; // continue
}

// Outer loop callback: process one position
static int sort_position_callback(__u32 i, void *data) {
	struct sort_outer_ctx *ctx = data;

	if (i >= ctx->positions) return 1;
	if (i >= ctx->n) return 1;

	/// manual assembly bounds check
	asm volatile(
	    "%[i] &= %[mask]"
		: [i] "+r" (i)
		: [mask] "i" (MAX_CANDIDATES - 1)
	);

	__u32 min_idx = i;
	s64 min_score = ctx->candidates[i].score;

	// Use bpf_loop for inner loop
	struct sort_inner_ctx inner_ctx = {
		.candidates = ctx->candidates,
		.n = ctx->n,
		.i = i,
		.min_idx = &min_idx,
		.min_score = &min_score,
	};

	__u32 inner_iterations = ctx->n - i - 1;
	if (inner_iterations > MAX_CANDIDATES - i - 1)
		inner_iterations = MAX_CANDIDATES - i - 1;

	bpf_loop(inner_iterations, find_min_callback, &inner_ctx, 0);

	// Swap if needed
	if (min_idx != i) {
       	asm volatile(
       	    "%[min_idx] &= %[mask]\n\t"
            "%[i] &= %[mask]\n\t"
      		: [min_idx] "+r" (min_idx)
            , [i] "+r" (i)
            : [mask] "i" (MAX_CANDIDATES - 1)
       	);
		struct candidate temp = ctx->candidates[i];
		ctx->candidates[i] = ctx->candidates[min_idx];
		ctx->candidates[min_idx] = temp;
	}

	return 0; // continue
}

// Partial selection sort using bpf_loop to reduce verifier complexity
static inline void sort_candidates(struct candidate candidates[MAX_CANDIDATES], __u32 n) {
	if (n <= 1) return;
	if (n > MAX_CANDIDATES) n = MAX_CANDIDATES;

	#define POSITIONS_TO_SORT 32

	__u32 positions = n < POSITIONS_TO_SORT ? n : POSITIONS_TO_SORT;

	struct sort_outer_ctx ctx = {
		.candidates = candidates,
		.n = n,
		.positions = positions,
	};

	bpf_loop(POSITIONS_TO_SORT, sort_position_callback, &ctx, 0);

	#undef POSITIONS_TO_SORT
}

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


// ML-enhanced iteration function for collecting candidates
static int mglru_ml_collect_fn(int idx, struct cache_ext_list_node *a)
{
	struct mglru_global_metadata *lrugen;
	int key__ = 0;
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);
	if (!lrugen) {
		bpf_printk("cache_ext: Failed to lookup lrugen metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}

	struct eviction_metadata *eviction_meta = get_eviction_metadata();
	if (!eviction_meta) {
		bpf_printk("cache_ext: ml_collect: Failed to get eviction metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}
	eviction_meta->iter_reached = idx;

	// Get folio metadata
	__u64 key = (__u64)a->folio;
	struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
		bpf_printk("cache_ext: ml_collect: Failed to lookup folio metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}

	int tier_threshold = eviction_meta->tier_threshold;
	int tier = lru_tier_from_refs(atomic_long_read(&meta->accesses));

	if (tier > tier_threshold) {
		update_protected_stat(lrugen, tier, folio_nr_pages(a->folio));
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}

	if (folio_test_locked(a->folio) || folio_test_writeback(a->folio) ||
	    folio_test_dirty(a->folio)) {
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}

	u32 cand_key = 0;
	__u64 fkey;

	__u32 *num_cand_ptr = bpf_map_lookup_elem(&num_candidates_map, &cand_key);
	if (!num_cand_ptr) {
		return CACHE_EXT_CONTINUE_ITER;
	}

	__u32 num_cand = *num_cand_ptr;
	if (num_cand >= MAX_CANDIDATES) {
		return CACHE_EXT_STOP_ITER;
	}

	struct candidate (*candidates)[MAX_CANDIDATES] = bpf_map_lookup_elem(&candidates_array, &cand_key);
	if (!candidates) {
		return CACHE_EXT_CONTINUE_ITER;
	}

	asm volatile(
		"%[num_cand] &= %[mask]"
		: [num_cand] "+r" (num_cand)
		: [mask] "i" (MAX_CANDIDATES - 1)
	);

	fkey = (__u64)a->folio;
	(*candidates)[num_cand].folio_addr = fkey;
	(*candidates)[num_cand].pages      = folio_nr_pages(a->folio);
	(*candidates)[num_cand].tier       =
		lru_tier_from_refs(atomic_long_read(&meta->accesses));
	(*candidates)[num_cand].score      = compute_ml_score(a->folio);

	*num_cand_ptr = num_cand + 1;

	return CACHE_EXT_CONTINUE_ITER;
}

// Original MGLRU iteration function (kept for fallback)
static int mglru_iter_fn(int idx, struct cache_ext_list_node *a)
{
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

	// relax candidates for ml
	int candidate_tier = tier_threshold > 0 ? tier_threshold - 1 : 0;

	struct eviction_metadata ev_meta = {
		.curr_gen = oldest_gen,
		.next_gen = next_gen,
		.tier_threshold = candidate_tier,
	};
	set_eviction_metadata(&ev_meta);

	assert_valid_gen_0(next_gen);

	// Initialize candidate collection
	u32 cand_key = 0;
	__u32 zero = 0;
	bpf_map_update_elem(&num_candidates_map, &cand_key, &zero, BPF_ANY);

	__u32 target_candidates = eviction_ctx->request_nr_folios_to_evict * 3;
	if (target_candidates > MAX_CANDIDATES) {
		target_candidates = MAX_CANDIDATES;
	}

	// ensure indices are within bounds for BPF verifier
	unsigned int next_gen_safe = next_gen & (MAX_NR_GENS - 1);
	unsigned int oldest_gen_safe = oldest_gen & (MAX_NR_GENS - 1);

	__u64 next_gen_list = mglru_lists[next_gen_safe];
	__u64 oldest_gen_list = mglru_lists[oldest_gen_safe];

	struct cache_ext_iterate_opts collect_opts = {
		.continue_list = next_gen_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	// bypass internal safeguard
	int original_nr_folios_to_evict = eviction_ctx->request_nr_folios_to_evict;
	eviction_ctx->request_nr_folios_to_evict *= 3;
	int ret = bpf_cache_ext_list_iterate_extended(
		memcg, oldest_gen_list, mglru_ml_collect_fn, &collect_opts, eviction_ctx);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to collect candidates\n");
		return;
	}

	// get number of candidates collected
	__u32 *num_cand_ptr = bpf_map_lookup_elem(&num_candidates_map, &cand_key);
	if (!num_cand_ptr) {
		bpf_printk("cache_ext: Failed to get num_candidates\n");
		return;
	}
	__u32 num_candidates = *num_cand_ptr;

	if (num_candidates == 0) {
		bpf_printk("cache_ext: No candidates collected\n");
		return;
	}

	struct candidate (*candidates)[MAX_CANDIDATES] = bpf_map_lookup_elem(&candidates_array, &cand_key);
	if (!candidates) {
		bpf_printk("cache_ext: Failed to get candidates array\n");
		return;
	}

	// Phase 3: Sort candidates by score (lower score = evict first)
	sort_candidates(*candidates, num_candidates);

	// Phase 4: Select worst N candidates for eviction
	__u32 num_to_evict = original_nr_folios_to_evict;
	if (num_to_evict > num_candidates) {
		num_to_evict = num_candidates;
	}

	// Phase 4: Fill eviction list with lowest-scoring candidates
	eviction_ctx->nr_folios_to_evict = 0;

    #define EVICT_LOOP_BODY(i) \
	do { \
		if ((i) < num_to_evict && (i) < 32) { \
			__u64 fkey = (*candidates)[(i)].folio_addr; \
			eviction_ctx->folios_to_evict[(i)] = (struct folio *)fkey; \
			eviction_ctx->nr_folios_to_evict++; \
			int tier  = (*candidates)[(i)].tier; \
			int pages = (*candidates)[(i)].pages; \
			update_evicted_stat(lrugen, tier, 1); \
			update_nr_pages_stat(lrugen, oldest_gen, -pages); \
		} \
	} while (0)

	EVICT_LOOP_BODY(0);
	EVICT_LOOP_BODY(1);
	EVICT_LOOP_BODY(2);
	EVICT_LOOP_BODY(3);
	EVICT_LOOP_BODY(4);
	EVICT_LOOP_BODY(5);
	EVICT_LOOP_BODY(6);
	EVICT_LOOP_BODY(7);
	EVICT_LOOP_BODY(8);
	EVICT_LOOP_BODY(9);
	EVICT_LOOP_BODY(10);
	EVICT_LOOP_BODY(11);
	EVICT_LOOP_BODY(12);
	EVICT_LOOP_BODY(13);
	EVICT_LOOP_BODY(14);
	EVICT_LOOP_BODY(15);
	EVICT_LOOP_BODY(16);
	EVICT_LOOP_BODY(17);
	EVICT_LOOP_BODY(18);
	EVICT_LOOP_BODY(19);
	EVICT_LOOP_BODY(20);
	EVICT_LOOP_BODY(21);
	EVICT_LOOP_BODY(22);
	EVICT_LOOP_BODY(23);
	EVICT_LOOP_BODY(24);
	EVICT_LOOP_BODY(25);
	EVICT_LOOP_BODY(26);
	EVICT_LOOP_BODY(27);
	EVICT_LOOP_BODY(28);
	EVICT_LOOP_BODY(29);
	EVICT_LOOP_BODY(30);
	EVICT_LOOP_BODY(31);

    #undef EVICT_LOOP_BODY

	// Phase 5: Update metadata for non-evicted candidates
	// All non-evicted candidates are already in next_gen_list (moved during iteration)
	// We need to update their metadata to match their physical location
	// - Hot candidates (tier > threshold): Update metadata + protected stats
	// - Cold candidates (tier <= threshold): Update metadata only

    #define PROMOTE_LOOP_BODY(i) \
	do { \
		if ((i) >= num_to_evict && (i) < num_candidates && (i) < MAX_CANDIDATES) { \
			__u64 fkey = (*candidates)[(i)].folio_addr; \
			struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &fkey); \
			if (meta) { \
				int tier  = (*candidates)[(i)].tier; \
				int pages = (*candidates)[(i)].pages; \
				update_nr_pages_stat(lrugen, oldest_gen, -pages); \
				update_nr_pages_stat(lrugen, next_gen, pages); \
				atomic_long_store(&meta->gen, next_gen); \
				if (tier > (int)tier_threshold && tier >= 1 && tier < MAX_NR_TIERS) { \
					update_protected_stat(lrugen, tier, pages); \
				} \
			} \
		} \
	} while (0)

	PROMOTE_LOOP_BODY(0);
	PROMOTE_LOOP_BODY(1);
	PROMOTE_LOOP_BODY(2);
	PROMOTE_LOOP_BODY(3);
	PROMOTE_LOOP_BODY(4);
	PROMOTE_LOOP_BODY(5);
	PROMOTE_LOOP_BODY(6);
	PROMOTE_LOOP_BODY(7);
	PROMOTE_LOOP_BODY(8);
	PROMOTE_LOOP_BODY(9);
	PROMOTE_LOOP_BODY(10);
	PROMOTE_LOOP_BODY(11);
	PROMOTE_LOOP_BODY(12);
	PROMOTE_LOOP_BODY(13);
	PROMOTE_LOOP_BODY(14);
	PROMOTE_LOOP_BODY(15);
	PROMOTE_LOOP_BODY(16);
	PROMOTE_LOOP_BODY(17);
	PROMOTE_LOOP_BODY(18);
	PROMOTE_LOOP_BODY(19);
	PROMOTE_LOOP_BODY(20);
	PROMOTE_LOOP_BODY(21);
	PROMOTE_LOOP_BODY(22);
	PROMOTE_LOOP_BODY(23);
	PROMOTE_LOOP_BODY(24);
	PROMOTE_LOOP_BODY(25);
	PROMOTE_LOOP_BODY(26);
	PROMOTE_LOOP_BODY(27);
	PROMOTE_LOOP_BODY(28);
	PROMOTE_LOOP_BODY(29);
	PROMOTE_LOOP_BODY(30);
	PROMOTE_LOOP_BODY(31);
	PROMOTE_LOOP_BODY(32);
	PROMOTE_LOOP_BODY(33);
	PROMOTE_LOOP_BODY(34);
	PROMOTE_LOOP_BODY(35);
	PROMOTE_LOOP_BODY(36);
	PROMOTE_LOOP_BODY(37);
	PROMOTE_LOOP_BODY(38);
	PROMOTE_LOOP_BODY(39);
	PROMOTE_LOOP_BODY(40);
	PROMOTE_LOOP_BODY(41);
	PROMOTE_LOOP_BODY(42);
	PROMOTE_LOOP_BODY(43);
	PROMOTE_LOOP_BODY(44);
	PROMOTE_LOOP_BODY(45);
	PROMOTE_LOOP_BODY(46);
	PROMOTE_LOOP_BODY(47);
	PROMOTE_LOOP_BODY(48);
	PROMOTE_LOOP_BODY(49);
	PROMOTE_LOOP_BODY(50);
	PROMOTE_LOOP_BODY(51);
	PROMOTE_LOOP_BODY(52);
	PROMOTE_LOOP_BODY(53);
	PROMOTE_LOOP_BODY(54);
	PROMOTE_LOOP_BODY(55);
	PROMOTE_LOOP_BODY(56);
	PROMOTE_LOOP_BODY(57);
	PROMOTE_LOOP_BODY(58);
	PROMOTE_LOOP_BODY(59);
	PROMOTE_LOOP_BODY(60);
	PROMOTE_LOOP_BODY(61);
	PROMOTE_LOOP_BODY(62);
	PROMOTE_LOOP_BODY(63);
	PROMOTE_LOOP_BODY(64);
	PROMOTE_LOOP_BODY(65);
	PROMOTE_LOOP_BODY(66);
	PROMOTE_LOOP_BODY(67);
	PROMOTE_LOOP_BODY(68);
	PROMOTE_LOOP_BODY(69);
	PROMOTE_LOOP_BODY(70);
	PROMOTE_LOOP_BODY(71);
	PROMOTE_LOOP_BODY(72);
	PROMOTE_LOOP_BODY(73);
	PROMOTE_LOOP_BODY(74);
	PROMOTE_LOOP_BODY(75);
	PROMOTE_LOOP_BODY(76);
	PROMOTE_LOOP_BODY(77);
	PROMOTE_LOOP_BODY(78);
	PROMOTE_LOOP_BODY(79);
	PROMOTE_LOOP_BODY(80);
	PROMOTE_LOOP_BODY(81);
	PROMOTE_LOOP_BODY(82);
	PROMOTE_LOOP_BODY(83);
	PROMOTE_LOOP_BODY(84);
	PROMOTE_LOOP_BODY(85);
	PROMOTE_LOOP_BODY(86);
	PROMOTE_LOOP_BODY(87);
	PROMOTE_LOOP_BODY(88);
	PROMOTE_LOOP_BODY(89);
	PROMOTE_LOOP_BODY(90);
	PROMOTE_LOOP_BODY(91);
	PROMOTE_LOOP_BODY(92);
	PROMOTE_LOOP_BODY(93);
	PROMOTE_LOOP_BODY(94);
	PROMOTE_LOOP_BODY(95);

    #undef PROMOTE_LOOP_BODY

	s64 success_evicted = eviction_ctx->nr_folios_to_evict;
	s64 failed_evicted = max(0, original_nr_folios_to_evict - eviction_ctx->nr_folios_to_evict);
	__sync_fetch_and_add(&lrugen->failed_evicted, failed_evicted);
	__sync_fetch_and_add(&lrugen->success_evicted, success_evicted);
	if (eviction_ctx->nr_folios_to_evict < original_nr_folios_to_evict) {
		bpf_printk("cache_ext: ML eviction: collected %d candidates, evicted %d/%d requested\n",
				num_candidates,
				eviction_ctx->nr_folios_to_evict,
				original_nr_folios_to_evict);
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
	bpf_printk("folio evicted");
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
struct cache_ext_ops mglru_ml_ops = {
	.init = (void *)mglru_init,
	.evict_folios = (void *)mglru_evict_folios,
	.folio_accessed = (void *)mglru_folio_accessed,
	.folio_evicted = (void *)mglru_folio_evicted,
	.folio_added = (void *)mglru_folio_added,
};

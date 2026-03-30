#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "cache_ext_mglru_lc.skel.h"
#include "dir_watcher.h"

char *USAGE = "Usage: ./cache_ext_mglru_lc --watch_dir <dir> --cgroup_path <path> [--log_dir <dir>]\n";
struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
	char *log_dir;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0,
					  "Directory to watch" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ "log_dir", 'l', "DIR", 0,
					  "Directory for log files (default: /var/log/cache_ext)" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
	case 'c':
		args->cgroup_path = arg;
		break;
	case 'l':
		args->log_dir = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

struct ring_buffer *rb_access = NULL;
struct ring_buffer *rb_insertion = NULL;
struct ring_buffer *rb_eviction = NULL;

// File descriptors for binary log files
static int access_log_fd = -1;
static int insertion_log_fd = -1;
static int eviction_log_fd = -1;

// Statistics counters
static uint64_t access_count = 0;
static uint64_t insertion_count = 0;
static uint64_t eviction_count = 0;

struct cache_access_fields {
	uint64_t timestamp;
	uint64_t page_time_delta;
	uint64_t page_time_delta2;
	uint64_t inode_time_delta;
	uint64_t inode_time_delta2;
	uint32_t major;
	uint32_t minor;
	uint64_t ino;
	uint64_t offset;
	uint32_t seq_distance;
	uint64_t file_size;
	uint32_t frequency;
	uint32_t inode_hotness_ema;
};

struct cache_insertion_event {
	uint64_t timestamp;
	uint32_t major;
	uint32_t minor;
	uint64_t ino;
	uint64_t index;
};

struct cache_eviction_event {
	uint64_t timestamp;
};

static int handle_access(void *ctx, void *data, size_t len)
{
	struct cache_access_fields *access_event = data;

	if (access_log_fd >= 0) {
		ssize_t written = write(access_log_fd, access_event, sizeof(*access_event));
		if (written != sizeof(*access_event)) {
			fprintf(stderr, "Failed to write access event\n");
		}
	}

	access_count++;
	if (access_count % 10000 == 0) {
		printf("Logged %lu access events\n", access_count);
	}

	return 0;
}

static int handle_insertion(void *ctx, void *data, size_t len)
{
	struct cache_insertion_event *insertion_event = data;

	if (insertion_log_fd >= 0) {
		ssize_t written = write(insertion_log_fd, insertion_event, sizeof(*insertion_event));
		if (written != sizeof(*insertion_event)) {
			fprintf(stderr, "Failed to write insertion event\n");
		}
	}

	insertion_count++;
	if (insertion_count % 10000 == 0) {
		printf("Logged %lu insertion events\n", insertion_count);
	}

	return 0;
}

static int handle_eviction(void *ctx, void *data, size_t len)
{
	struct cache_eviction_event *eviction_event = data;

	if (eviction_log_fd >= 0) {
		ssize_t written = write(eviction_log_fd, eviction_event, sizeof(*eviction_event));
		if (written != sizeof(*eviction_event)) {
			fprintf(stderr, "Failed to write eviction event\n");
		}
	}

	eviction_count++;
	if (eviction_count % 100 == 0) {
		printf("Logged %lu eviction events\n", eviction_count);
	}

	return 0;
}

static void cleanup_logs()
{
	if (access_log_fd >= 0) {
		close(access_log_fd);
		access_log_fd = -1;
	}
	if (insertion_log_fd >= 0) {
		close(insertion_log_fd);
		insertion_log_fd = -1;
	}
	if (eviction_log_fd >= 0) {
		close(eviction_log_fd);
		eviction_log_fd = -1;
	}
	if (rb_access) {
		ring_buffer__free(rb_access);
		rb_access = NULL;
	}
	if (rb_insertion) {
		ring_buffer__free(rb_insertion);
		rb_insertion = NULL;
	}
	if (rb_eviction) {
		ring_buffer__free(rb_eviction);
		rb_eviction = NULL;
	}
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_mglru_lc_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, NULL, NULL };

	if (argp_parse(&argp, argc, argv, 0, 0, &args) != 0) {
		fprintf(stderr, "%s", USAGE);
		return 1;
	}

	if (!args.watch_dir || !args.cgroup_path) {
		fprintf(stderr, "Error: --watch_dir and --cgroup_path are required\n");
		fprintf(stderr, "%s", USAGE);
		return 1;
	}

	// Check if watch_dir exists
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", args.watch_dir);
		return 1;
	}

	// Get full path for watch directory
	char watch_dir_full_path[PATH_MAX];
	if (!realpath(args.watch_dir, watch_dir_full_path)) {
		perror("realpath");
		return 1;
	}

	// Check path length (BPF limitation)
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long (max 128 chars)\n");
		return 1;
	}

	// Set default log directory
	if (!args.log_dir) {
		args.log_dir = "/var/log/cache_ext";
	}

	// Create log directory if it doesn't exist
	mkdir(args.log_dir, 0755);

	// Open log files
	char access_log_path[PATH_MAX];
	char insertion_log_path[PATH_MAX];
	char eviction_log_path[PATH_MAX];
	time_t now = time(NULL);

	snprintf(access_log_path, sizeof(access_log_path),
		 "%s/mglru_lc_access_%ld.bin", args.log_dir, now);
	snprintf(insertion_log_path, sizeof(insertion_log_path),
		 "%s/mglru_lc_insertion_%ld.bin", args.log_dir, now);
	snprintf(eviction_log_path, sizeof(eviction_log_path),
		 "%s/mglru_lc_eviction_%ld.bin", args.log_dir, now);

	access_log_fd = open(access_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (access_log_fd < 0) {
		perror("Failed to open access log file");
		goto cleanup;
	}

	insertion_log_fd = open(insertion_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (insertion_log_fd < 0) {
		perror("Failed to open insertion log file");
		goto cleanup;
	}

	eviction_log_fd = open(eviction_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (eviction_log_fd < 0) {
		perror("Failed to open eviction log file");
		goto cleanup;
	}

	printf("Logging to:\n");
	printf("  Access:    %s\n", access_log_path);
	printf("  Insertion: %s\n", insertion_log_path);
	printf("  Eviction:  %s\n", eviction_log_path);

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		goto cleanup;
	}

	// Load and verify BPF application
	skel = cache_ext_mglru_lc_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Set watch directory path in BPF rodata
	skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
	strcpy((char *)skel->rodata->watch_dir_path, watch_dir_full_path);

	printf("Watching directory: %s\n", watch_dir_full_path);

	// Load BPF program
	ret = cache_ext_mglru_lc_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Initialize directory watcher (populate inode watchlist) - AFTER load
	if (initialize_watch_dir_map(args.watch_dir,
	                 bpf_map__fd(skel->maps.inode_watchlist), true) != 0) {
		perror("Failed to initialize directory watcher");
		goto cleanup;
	}

	// Attach struct_ops
	link = bpf_map__attach_cache_ext_ops(skel->maps.mglru_lc_ops, cgroup_fd);
	if (!link) {
		perror("Failed to attach cache_ext_ops");
		goto cleanup;
	}

	printf("Successfully attached cache_ext_ops to %s\n", args.cgroup_path);

	// Attach probes (including vfs_open fexit for directory watcher)
	ret = cache_ext_mglru_lc_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF probes");
		goto cleanup;
	}
	printf("Successfully attached BPF probes\n");

	// Set up ring buffers
	rb_access = ring_buffer__new(bpf_map__fd(skel->maps.rb_access),
				     handle_access, NULL, NULL);
	if (!rb_access) {
		fprintf(stderr, "Failed to create access ring buffer\n");
		goto cleanup;
	}

	rb_insertion = ring_buffer__new(bpf_map__fd(skel->maps.rb_insertion),
					handle_insertion, NULL, NULL);
	if (!rb_insertion) {
		fprintf(stderr, "Failed to create insertion ring buffer\n");
		goto cleanup;
	}

	rb_eviction = ring_buffer__new(bpf_map__fd(skel->maps.rb_eviction),
				       handle_eviction, NULL, NULL);
	if (!rb_eviction) {
		fprintf(stderr, "Failed to create eviction ring buffer\n");
		goto cleanup;
	}

	printf("MGLRU-LC policy loaded successfully\n");
	printf("Press Ctrl+C to exit\n");

	// Poll ring buffers
	while (1) {
		ret = ring_buffer__poll(rb_access, 100);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Error polling access ring buffer: %d\n", ret);
			break;
		}

		ret = ring_buffer__poll(rb_insertion, 100);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Error polling insertion ring buffer: %d\n", ret);
			break;
		}

		ret = ring_buffer__poll(rb_eviction, 100);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Error polling eviction ring buffer: %d\n", ret);
			break;
		}
	}

	ret = 0;

cleanup:
	cleanup_logs();
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mglru_lc_bpf__destroy(skel);

	printf("\nFinal statistics:\n");
	printf("  Access events:    %lu\n", access_count);
	printf("  Insertion events: %lu\n", insertion_count);
	printf("  Eviction events:  %lu\n", eviction_count);

	return ret;
}

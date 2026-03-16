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

#include "cache_ext_mglru_ml.skel.h"
#include "dir_watcher.h"

// For JSON parsing
#include <json-c/json.h>

#define NUM_MODEL_FEATURES 9
#define MAX_BINS 10

char *USAGE = "Usage: ./cache_ext_mglru_ml --watch_dir <dir> --cgroup_path <path> --model_file <json> [--log_dir <dir>]\n";
struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
	char *log_dir;
	char *model_file;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0,
					  "Directory to watch" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ "log_dir", 'l', "DIR", 0,
					  "Directory for log files (default: /var/log/cache_ext)" },
					{ "model_file", 'm', "FILE", 0,
					  "Path to model weights JSON file" },
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
	case 'm':
		args->model_file = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

struct ring_buffer *rb_access = NULL;
struct ring_buffer *rb_insertion = NULL;

// File descriptors for binary log files
static int access_log_fd = -1;
static int insertion_log_fd = -1;

// Statistics counters
static uint64_t access_count = 0;
static uint64_t insertion_count = 0;

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
	if (rb_access) {
		ring_buffer__free(rb_access);
		rb_access = NULL;
	}
	if (rb_insertion) {
		ring_buffer__free(rb_insertion);
		rb_insertion = NULL;
	}
}

static int load_model_weights(const char *model_file, struct cache_ext_mglru_ml_bpf *skel)
{
	FILE *fp = fopen(model_file, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open model file %s: %s\n", model_file, strerror(errno));
		return -1;
	}

	// Read entire file
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *json_str = malloc(fsize + 1);
	if (!json_str) {
		fclose(fp);
		return -1;
	}

	fread(json_str, 1, fsize, fp);
	json_str[fsize] = 0;
	fclose(fp);

	// Parse JSON
	struct json_object *root = json_tokener_parse(json_str);
	free(json_str);

	if (!root) {
		fprintf(stderr, "Failed to parse JSON from %s\n", model_file);
		return -1;
	}

	// Get features array
	struct json_object *features_arr;
	if (!json_object_object_get_ex(root, "features", &features_arr)) {
		fprintf(stderr, "Missing 'features' in JSON\n");
		json_object_put(root);
		return -1;
	}

	int n_features = json_object_array_length(features_arr);
	if (n_features != NUM_MODEL_FEATURES) {
		fprintf(stderr, "Expected %d features, got %d\n", NUM_MODEL_FEATURES, n_features);
		json_object_put(root);
		return -1;
	}

	// Get map file descriptors
	int n_bins_fd = bpf_map__fd(skel->maps.n_bins_map);
	int bin_edges_fd = bpf_map__fd(skel->maps.bin_edges_map);
	int nn_weights_fd = bpf_map__fd(skel->maps.nn_weights_map);

	printf("Loading model weights into BPF maps...\n");

	// Load each feature
	for (int feat_idx = 0; feat_idx < n_features; feat_idx++) {
		struct json_object *feat_obj = json_object_array_get_idx(features_arr, feat_idx);

		// Get feature name
		struct json_object *name_obj;
		json_object_object_get_ex(feat_obj, "name", &name_obj);
		const char *feat_name = json_object_get_string(name_obj);

		// Get n_bins
		struct json_object *n_bins_obj;
		json_object_object_get_ex(feat_obj, "n_bins", &n_bins_obj);
		__u8 n_bins = (__u8)json_object_get_int(n_bins_obj);

		// Get bin_edges
		struct json_object *bin_edges_arr;
		json_object_object_get_ex(feat_obj, "bin_edges", &bin_edges_arr);
		int n_edges = json_object_array_length(bin_edges_arr);

		__u64 bin_edges[MAX_BINS];
		for (int i = 0; i < n_edges && i < MAX_BINS; i++) {
			struct json_object *edge_obj = json_object_array_get_idx(bin_edges_arr, i);
			bin_edges[i] = json_object_get_int(edge_obj);
		}

		// Get weights_int
		struct json_object *weights_arr;
		json_object_object_get_ex(feat_obj, "weights_int", &weights_arr);
		int n_weights = json_object_array_length(weights_arr);

		int64_t weights[MAX_BINS];
		for (int i = 0; i < n_weights && i < MAX_BINS; i++) {
			struct json_object *weight_obj = json_object_array_get_idx(weights_arr, i);
			weights[i] = (int64_t)json_object_get_int64(weight_obj);
		}

		// Update BPF maps
		__u32 key = feat_idx;
		if (bpf_map_update_elem(n_bins_fd, &key, &n_bins, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to update n_bins_map for feature %d\n", feat_idx);
			json_object_put(root);
			return -1;
		}

		if (bpf_map_update_elem(bin_edges_fd, &key, bin_edges, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to update bin_edges_map for feature %d\n", feat_idx);
			json_object_put(root);
			return -1;
		}

		if (bpf_map_update_elem(nn_weights_fd, &key, weights, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to update nn_weights_map for feature %d\n", feat_idx);
			json_object_put(root);
			return -1;
		}

		printf("  Loaded feature %d (%s): %d bins, %d weights\n",
		       feat_idx, feat_name, n_bins, n_weights);
	}

	json_object_put(root);
	printf("Model weights loaded successfully!\n");
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_mglru_ml_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { .log_dir = "/var/log/cache_ext" };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
	if (args.watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	if (args.model_file == NULL) {
		fprintf(stderr, "Missing required argument: model_file\n");
		return 1;
	}

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", args.watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Open skel
	skel = cache_ext_mglru_ml_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	printf("Starting cache_ext_mglru_ml (ML-enhanced MGLRU)\n");

	// Set watch_dir
	skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
	strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

	// Load programs
	ret = cache_ext_mglru_ml_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Load model weights into BPF maps
	ret = load_model_weights(args.model_file, skel);
	if (ret) {
		fprintf(stderr, "Failed to load model weights\n");
		goto cleanup;
	}

	// Initialize inode_watchlist map
	ret = initialize_watch_dir_map(args.watch_dir,
				       bpf_map__fd(skel->maps.inode_watchlist), true);
	if (ret) {
		perror("Failed to initialize inode watchlist map");
		goto cleanup;
	}

	// Setup logging if log_dir is specified
	if (args.log_dir) {
		mkdir(args.log_dir, 0755);

		char access_log_path[PATH_MAX];
		char insertion_log_path[PATH_MAX];
		time_t now = time(NULL);
		snprintf(access_log_path, sizeof(access_log_path),
			 "%s/access_%ld.bin", args.log_dir, now);
		snprintf(insertion_log_path, sizeof(insertion_log_path),
			 "%s/insertion_%ld.bin", args.log_dir, now);

		access_log_fd = open(access_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		insertion_log_fd = open(insertion_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (access_log_fd < 0 || insertion_log_fd < 0) {
			fprintf(stderr, "Warning: Failed to open log files\n");
		} else {
			printf("Logging to:\n  %s\n  %s\n", access_log_path, insertion_log_path);
		}

		// Setup ring buffers
		rb_access = ring_buffer__new(bpf_map__fd(skel->maps.rb_access),
					      handle_access, NULL, NULL);
		rb_insertion = ring_buffer__new(bpf_map__fd(skel->maps.rb_insertion),
						handle_insertion, NULL, NULL);
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mglru_ml_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach BPF cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Attach probes
	ret = cache_ext_mglru_ml_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF programs");
		goto cleanup;
	}

	printf("Successfully attached. Press Ctrl-C to exit.\n");

	// Poll ring buffers if logging is enabled
	if (rb_access && rb_insertion) {
		while (1) {
			ring_buffer__poll(rb_access, 100);
			ring_buffer__poll(rb_insertion, 100);
		}
	} else {
		// Wait for keyboard input
		getchar();
	}

cleanup:
	cleanup_logs();
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mglru_ml_bpf__destroy(skel);
	return 0;
}

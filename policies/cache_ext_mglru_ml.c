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
    uint64_t timestamp;        // ts: bpf_ktime_get_ns()
    uint64_t page_time_delta;  // pd: delta since last page access (ns)
    uint64_t page_time_delta2; // p2: delta since last two page access (ns)
    uint64_t inode_time_delta; // id: delta since last inode access (ns)
    uint64_t inode_time_delta2;// i2: delta since last two inode access (ns)
    uint32_t major;            // dm: device major
    uint32_t minor;            // dn: device minor
    uint64_t ino;              // in: inode number (i_ino)
    uint64_t offset;           // of: page index (folio index)
    uint32_t seq_distance;     // sd: pages away from last inode offset
    uint64_t file_size;        // sz: file size
    uint32_t frequency;        // fq: frequency
    uint32_t inode_hotness_ema;// ie: inode hotness EMA
};

struct cache_insertion_event {
    uint64_t timestamp;   /* t: bpf_ktime_get_ns() */
    uint32_t major;       /* d: device major */
    uint32_t minor;       /* d: device minor */
    uint64_t ino;         /* i: inode number (data.i_ino) */
    uint64_t index;       /* x: page index (data.index) */
};

static int handle_access(void *ctx, void *data, size_t len)
{
    struct cache_access_fields *access_event = data;

    if (access_log_fd >= 0) {
        ssize_t written = write(access_log_fd, access_event, sizeof(*access_event));
        if (written != sizeof(*access_event)) {
            fprintf(stderr, "Failed to write access event: %s\n", strerror(errno));
        } else {
            access_count++;
        }
    }

    return 0;
}

static int handle_insertion(void *ctx, void *data, size_t len)
{
    struct cache_insertion_event *insertion_event = data;

    if (insertion_log_fd >= 0) {
        ssize_t written = write(insertion_log_fd, insertion_event, sizeof(*insertion_event));
        if (written != sizeof(*insertion_event)) {
            fprintf(stderr, "Failed to write insertion event: %s\n", strerror(errno));
        } else {
            insertion_count++;
        }
    }

    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int open_log_file(const char *log_dir, const char *filename)
{
	char filepath[PATH_MAX];
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char timestamp[64];

	strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
	snprintf(filepath, sizeof(filepath), "%s/%s_%s.bin", log_dir, filename, timestamp);

	int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to open log file %s: %s\n", filepath, strerror(errno));
		return -1;
	}

	printf("Logging to: %s\n", filepath);
	return fd;
}

#define MAX_BINS 10
#define NUM_MODEL_FEATURES 8

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
			bin_edges[i] = (__u64)json_object_get_double(edge_obj);
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

	// Set up signal handler
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
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

	// Set default log directory if not specified
	if (args.log_dir == NULL) {
		args.log_dir = "/var/log/cache_ext";
	}

	// Create log directory if it doesn't exist
	struct stat st = {0};
	if (stat(args.log_dir, &st) == -1) {
		if (mkdir(args.log_dir, 0755) == -1) {
			fprintf(stderr, "Failed to create log directory %s: %s\n",
				args.log_dir, strerror(errno));
			return 1;
		}
	}

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n",
			args.watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// TODO: Enable longer length
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

	// Open log files
	access_log_fd = open_log_file(args.log_dir, "cache_access");
	if (access_log_fd < 0) {
		fprintf(stderr, "Failed to open access log file\n");
		goto cleanup;
	}

	insertion_log_fd = open_log_file(args.log_dir, "cache_insertion");
	if (insertion_log_fd < 0) {
		fprintf(stderr, "Failed to open insertion log file\n");
		goto cleanup;
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
				       bpf_map__fd(skel->maps.inode_watchlist), false);

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mglru_ml_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Attach probes
	ret = cache_ext_mglru_ml_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF programs");
		goto cleanup;
	}

	rb_access = ring_buffer__new(bpf_map__fd(skel->maps.rb_access), handle_access, NULL, NULL);
	if (!rb_access) {
		perror("Failed to create ring buffer for access events");
		goto cleanup;
	}

    rb_insertion = ring_buffer__new(bpf_map__fd(skel->maps.rb_insertion), handle_insertion, NULL, NULL);
    if (!rb_insertion) {
        perror("Failed to create ring buffer for insertion events");
        goto cleanup;
    }

	printf("Successfully attached. Logging to binary files. Press Ctrl+C to exit...\n");

	time_t last_stats_time = time(NULL);
	while (!exiting) {
		int err;

        err = ring_buffer__poll(rb_access, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling access ring buffer: %d\n", err);
            break;
        }

        err = ring_buffer__poll(rb_insertion, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling insertion ring buffer: %d\n", err);
            break;
        }

        // Print statistics every 10 seconds
        time_t now = time(NULL);
        if (now - last_stats_time >= 10) {
            printf("Stats: %lu access events, %lu insertion events",
                   access_count, insertion_count);
            last_stats_time = now;
        }
	}

	printf("\nExiting...\n");
	printf("Final stats: %lu access events, %lu insertion events\n",
	       access_count, insertion_count);

	ret = 0;

cleanup:
    if (rb_access)
        ring_buffer__free(rb_access);
    if (rb_insertion)
        ring_buffer__free(rb_insertion);
    if (access_log_fd >= 0) {
        fsync(access_log_fd);
        close(access_log_fd);
    }
    if (insertion_log_fd >= 0) {
        fsync(insertion_log_fd);
        close(insertion_log_fd);
    }
    /* no logger file to close; logger printed to stdout */
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    bpf_link__destroy(link);
    cache_ext_mglru_ml_bpf__destroy(skel);
    return ret;
}

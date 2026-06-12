#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_ml_sampling.skel.h"
#include "dir_watcher.h"

// For JSON parsing
#include <json-c/json.h>

#define NUM_MODEL_FEATURES 9
#define MAX_BINS 10

char *USAGE =
	"Usage: ./cache_ext_ml_sampling --watch_dir <dir> --cgroup_path <path> --model_file <json>\n";

struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
	char *model_file;
};

// Must match struct model_meta in cache_ext_ml_sampling.bpf.c.
struct model_meta {
	int64_t bias;
	int64_t threshold;
};

static struct argp_option options[] = {
	{ "watch_dir", 'w', "DIR", 0, "Directory to watch" },
	{ "cgroup_path", 'c', "PATH", 0,
	  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	{ "model_file", 'm', "FILE", 0, "Path to model weights JSON file" },
	{ 0 }
};

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
	case 'm':
		args->model_file = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

// Read a required integer field from a JSON object.
static int json_get_int64(struct json_object *obj, const char *key, int64_t *out)
{
	struct json_object *field;
	if (!json_object_object_get_ex(obj, key, &field)) {
		fprintf(stderr, "Missing '%s' in JSON\n", key);
		return -1;
	}
	*out = (int64_t)json_object_get_int64(field);
	return 0;
}

static int load_model_weights(const char *model_file,
			      struct cache_ext_ml_sampling_bpf *skel)
{
	FILE *fp = fopen(model_file, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open model file %s: %s\n", model_file,
			strerror(errno));
		return -1;
	}

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

	struct json_object *root = json_tokener_parse(json_str);
	free(json_str);
	if (!root) {
		fprintf(stderr, "Failed to parse JSON from %s\n", model_file);
		return -1;
	}

	struct json_object *features_arr;
	if (!json_object_object_get_ex(root, "features", &features_arr)) {
		fprintf(stderr, "Missing 'features' in JSON\n");
		json_object_put(root);
		return -1;
	}

	int n_features = json_object_array_length(features_arr);
	if (n_features != NUM_MODEL_FEATURES) {
		fprintf(stderr, "Expected %d features, got %d\n", NUM_MODEL_FEATURES,
			n_features);
		json_object_put(root);
		return -1;
	}

	int n_bins_fd = bpf_map__fd(skel->maps.n_bins_map);
	int bin_edges_fd = bpf_map__fd(skel->maps.bin_edges_map);
	int nn_weights_fd = bpf_map__fd(skel->maps.nn_weights_map);
	int model_meta_fd = bpf_map__fd(skel->maps.model_meta_map);

	printf("Loading model weights into BPF maps...\n");

	for (int feat_idx = 0; feat_idx < n_features; feat_idx++) {
		struct json_object *feat_obj =
			json_object_array_get_idx(features_arr, feat_idx);

		struct json_object *name_obj;
		json_object_object_get_ex(feat_obj, "name", &name_obj);
		const char *feat_name = json_object_get_string(name_obj);

		struct json_object *n_bins_obj;
		json_object_object_get_ex(feat_obj, "n_bins", &n_bins_obj);
		__u8 n_bins = (__u8)json_object_get_int(n_bins_obj);
		if (n_bins == 0 || n_bins > MAX_BINS) {
			fprintf(stderr, "Invalid n_bins for feature %d: %u\n", feat_idx,
				n_bins);
			json_object_put(root);
			return -1;
		}

		struct json_object *bin_edges_arr;
		json_object_object_get_ex(feat_obj, "bin_edges", &bin_edges_arr);
		int n_edges = json_object_array_length(bin_edges_arr);
		if (n_edges != n_bins - 1) {
			fprintf(stderr,
				"Invalid bin_edges length for feature %d: expected %u, got %d\n",
				feat_idx, n_bins - 1, n_edges);
			json_object_put(root);
			return -1;
		}

		__u64 bin_edges[MAX_BINS] = {};
		for (int i = 0; i < n_edges && i < MAX_BINS; i++) {
			struct json_object *edge_obj =
				json_object_array_get_idx(bin_edges_arr, i);
			bin_edges[i] = json_object_get_uint64(edge_obj);
		}

		struct json_object *weights_arr;
		json_object_object_get_ex(feat_obj, "weights_int", &weights_arr);
		int n_weights = json_object_array_length(weights_arr);
		if (n_weights != n_bins) {
			fprintf(stderr,
				"Invalid weights_int length for feature %d: expected %u, got %d\n",
				feat_idx, n_bins, n_weights);
			json_object_put(root);
			return -1;
		}

		int64_t weights[MAX_BINS] = {};
		for (int i = 0; i < n_weights && i < MAX_BINS; i++) {
			struct json_object *weight_obj =
				json_object_array_get_idx(weights_arr, i);
			weights[i] = (int64_t)json_object_get_int64(weight_obj);
		}

		__u32 key = feat_idx;
		if (bpf_map_update_elem(n_bins_fd, &key, &n_bins, BPF_ANY) != 0 ||
		    bpf_map_update_elem(bin_edges_fd, &key, bin_edges, BPF_ANY) != 0 ||
		    bpf_map_update_elem(nn_weights_fd, &key, weights, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to update model maps for feature %d\n",
				feat_idx);
			json_object_put(root);
			return -1;
		}

		printf("  Loaded feature %d (%s): %d bins, %d weights\n", feat_idx,
		       feat_name, n_bins, n_weights);
	}

	// Bias + decision threshold (quantized). Unused for ranking but loaded
	// to keep the model artifact contract identical to fifo_ml_protect.
	struct model_meta meta = { 0, 0 };
	if (json_get_int64(root, "bias_int", &meta.bias) != 0 ||
	    json_get_int64(root, "threshold_int", &meta.threshold) != 0) {
		json_object_put(root);
		return -1;
	}
	__u32 meta_key = 0;
	if (bpf_map_update_elem(model_meta_fd, &meta_key, &meta, BPF_ANY) != 0) {
		fprintf(stderr, "Failed to update model_meta_map\n");
		json_object_put(root);
		return -1;
	}
	printf("  bias=%lld threshold=%lld\n", (long long)meta.bias,
	       (long long)meta.threshold);

	json_object_put(root);
	printf("Model weights loaded successfully!\n");
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_ml_sampling_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	/* stdout is redirected to a log file by the bench harness; line-buffer it
	 * so startup/progress lines survive the SIGINT kill at teardown. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (args.watch_dir == NULL || args.cgroup_path == NULL ||
	    args.model_file == NULL) {
		fprintf(stderr, "%s", USAGE);
		return 1;
	}

	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", args.watch_dir);
		return 1;
	}

	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_ml_sampling_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	printf("Starting cache_ext_ml_sampling (sampled model-ranked eviction)\n");

	skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
	strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

	ret = cache_ext_ml_sampling_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	ret = load_model_weights(args.model_file, skel);
	if (ret) {
		fprintf(stderr, "Failed to load model weights\n");
		goto cleanup;
	}

	ret = initialize_watch_dir_map(args.watch_dir,
				       bpf_map__fd(skel->maps.inode_watchlist), true);
	if (ret) {
		perror("Failed to initialize inode watchlist map");
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.ml_sampling_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach BPF cache_ext_ops to cgroup");
		goto cleanup;
	}

	ret = cache_ext_ml_sampling_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF programs");
		goto cleanup;
	}

	printf("Successfully attached. Press Ctrl-C to exit.\n");
	/* getchar() returns EOF immediately when stdin is /dev/null (nohup),
	 * which would silently detach the policy mid-benchmark. Sleep until a
	 * signal terminates us instead. */
	for (;;)
		pause();

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_ml_sampling_bpf__destroy(skel);
	return ret;
}

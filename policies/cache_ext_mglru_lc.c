#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>

#include "cache_ext_mglru_lc.skel.h"
#include "dir_watcher.h"

char *USAGE = "Usage: ./cache_ext_mglru --watch_dir <dir> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0,
					  "Directory to watch" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
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
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char *program_name = "";

struct ring_buffer *rb_access = NULL;
struct ring_buffer *rb_insertion = NULL;

struct cache_access_fields {
    uint64_t timestamp;      // a: bpf_ktime_get_ns()
    uint64_t time_delta;     // t: delta since last access (ns)
    uint32_t major;          // d: device major
    uint32_t minor;          // d: device minor
    uint64_t ino;            // i: inode number (i_ino)
    uint64_t offset;         // o: page index (folio index)
    bool is_sequential;  // s: boolean (0 or 1)
    uint64_t file_size;      // z: file size
    uint32_t frequency;      // f: frequency
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
    syslog(
        LOG_INFO,
        "tracer-cache-access: a=%lu t=%lu d=%u:%u i=%lu o=%lu s=%u z=%lu f=%u\n",
        access_event->timestamp,
        access_event->time_delta,
        access_event->major,
        access_event->minor,
        access_event->ino,
        access_event->offset,
        access_event->is_sequential ? 1 : 0,
        access_event->file_size,
        access_event->frequency
    );
    return 0;
}

static int handle_insertion(void *ctx, void *data, size_t len)
{
    struct cache_insertion_event *insertion_event = data;
    syslog(
        LOG_INFO,
        "tracer-cache-insertion: t=%lu d=%u:%u i=%lu x=%lu\n",
        insertion_event->timestamp,
        insertion_event->major,
        insertion_event->minor,
        insertion_event->ino,
        insertion_event->index
    );
    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_mglru_lc_bpf *skel = NULL;
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

	// Open skel
	skel = cache_ext_mglru_lc_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// enable syslog
	openlog(program_name, LOG_CONS, LOG_USER);
	fprintf(stderr, "started syslog");
	syslog(LOG_INFO, "tracer: Starting cache_ext_mglru_lc");

	// Set watch_dir
	skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
	strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

	// Load programs
	ret = cache_ext_mglru_lc_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Initialize inode_watchlist map
	ret = initialize_watch_dir_map(args.watch_dir,
				       bpf_map__fd(skel->maps.inode_watchlist), false);

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mglru_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Attach probes
	ret = cache_ext_mglru_lc_bpf__attach(skel);
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

	printf("Successfully attached. Logging to syslog. Press Ctrl+C to exit...\n");

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
	}

	printf("\nExiting...\n");

	ret = 0;

cleanup:
	if (rb_access)
		ring_buffer__free(rb_access);
	if (rb_insertion)
		ring_buffer__free(rb_insertion);
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mglru_lc_bpf__destroy(skel);
	closelog();
	return ret;
}

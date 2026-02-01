# MGLRU_LC data collection script

This script runs mglru_lc (MGLRU with learnedcache) under a filebench workload.

## Usage

```bash
./run.sh <workload_file>
```

Example:
```bash
./run.sh ~/workloads/fileserver.f
```

## Output

- **Syslog traces**: Sent to host machine at `192.168.33.1:514`
  - Cache access events: `tracer_cache_access: a=... t=... d=... i=... o=... s=... z=... f=...`
  - Cache insertion events: `tracer_cache_insertion: t=... d=... i=... x=...`

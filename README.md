# LearnedCache: A Novel eBPF-Driven Neural Model for Page Cache Eviction in the Linux Kernel

[![arXiv](https://img.shields.io/badge/arXiv-2605.26168-b31b1b.svg)](https://arxiv.org/abs/2605.26168)

This repository contains the tracers and policies for LearnedCache. The developed FIFO policies can be found in `/policies`, and harnesses can be found in `/lc-bench` and `/lc-eval`. This repository is a modified fork of the source code and scripts for [cache_ext](https://dl.acm.org/doi/10.1145/3731569.3764820), the framework used for implementation. If using cache_ext, please cite the reference [below](#citation).

## Getting Started

This section is adapted from the [`cache_ext` repository](https://github.com/cache-ext/cache_ext).

On cloud machines, `/mydata` is typically owned by root. Change ownership before cloning:

```sh
sudo chown -R $USER:$(id -gn) /mydata
```

First, clone the repo and
initialize the submodules:

```sh
cd /mydata
git clone https://github.com/JayAndJef/cache_ext_lc.git
cd cache_ext_lc
git submodule update --init --recursive
```

Setup is split into two manual scripts (no cron/automation). Run part 1, let
the machine reboot into the cache-ext kernel, then run part 2 yourself.

**Part 1 — install the kernel and reboot:**

```sh
./setup_phase1.sh
```

This compiles/installs the custom Linux kernel (including libbpf and bpftool),
selects it for the next boot, and reboots. (To do this by hand instead, run
`./install_kernel.sh`, then `sudo grub-reboot "Advanced options for
Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+"` and `sudo reboot now`.)

**Part 2 — finish setup after the reboot:**

Once the machine comes back up on the cache-ext kernel, run:

```sh
./setup_phase2.sh
```

This installs misc packages, downloads the LevelDB database, and builds LevelDB,
My-YCSB, and the BPF policies. It hard-fails if you are not on the cache-ext
kernel. Tip: run it under a log, e.g. `./setup_phase2.sh 2>&1 | tee setup_phase2.log`.

Then, the scripts located in `/lc-eval` can be used to run the modified policies.

## Citation

If using cache_ext, please include the following citation:

```bibtex
@inproceedings{cacheext,
author = {Zussman, Tal and Zarkadas, Ioannis and Carin, Jeremy and Cheng, Andrew and Franke, Hubertus and Pfefferle, Jonas and Cidon, Asaf},
title = {cache_ext: Customizing the Page Cache with eBPF},
year = {2025},
isbn = {9798400718700},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3731569.3764820},
doi = {10.1145/3731569.3764820},
pages = {462–478},
numpages = {17},
keywords = {operating systems, eBPF, page cache},
location = {Lotte Hotel World, Seoul, Republic of Korea},
series = {SOSP '25}
}
```

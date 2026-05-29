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

Next, you must compile and install the custom Linux kernel:

```sh
./install_kernel.sh
```

This will also set up libbpf and bpftool.

After the kernel is compiled and installed, you will be prompted to reboot into
cache_ext kernel:

```sh
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+"
sudo reboot now
```

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

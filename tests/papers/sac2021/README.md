# Introduction

These are the raw results that were used to present the results in:

 Matthew Bradbury, Arshad Jhumka and Tim Watson.
 Trust Assessment in 32 KiB of RAM: Multi-application Trust-based Task Offloading for Resource-constrained IoT Nodes.
 Proceedings of the Symposium on Applied Computing, ACM, 2021, 1-10.

Generating the graphs requires scripts from: [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc)

# Reproducing Results

In order to reproduce the results, the setup instructions provided at [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc) should first be followed.

Then the test scripts in tests/run need to be edited to match the configuration used for these experiments. Six nodes were used, one configured as the root, two as edges and three as wsn nodes. The start script for edge needs to be edited differently on rr2 and rr6 to contain the correct configurations.

On rr2:
```bash
./tests/papers/sac2021/edge-always-good.sh
```

On rr6:
```bash
./tests/papers/sac2021/edge-always-bad.sh
```

# Generating Graphs and Tables

## Table 2

```bash
make -C wsn TRUST_MODEl=basic TRUST_CHOOSE=banded
./tools/binprof.py wsn/edge/edge.zoul
```

## Table 4

```bash
make -C wsn TRUST_MODEl=basic TRUST_CHOOSE=banded
./tools/binprof.py wsn/edge/edge.zoul
```

## Table 5

```bash
./analysis/parser/profile_pyterm.py --log-dir results/2020-08-28-profile
./analysis/parser/profile_pyterm.py --log-dir results/2020-09-01-profile-aes-ccm
```

## Figure 8

```bash
./analysis/graph/trust_choose_evolution.py --log-dir results/2020-09-10-bad-routing-for-paper
```

## Figure 10

```bash
./analysis/graph/messages.py --log-dir results/2020-09-10-bad-routing-for-paper
```

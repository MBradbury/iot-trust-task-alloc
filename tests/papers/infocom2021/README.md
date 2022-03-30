# Introduction

These are the raw results that were used to present the results in:

 Matthew Bradbury, Arshad Jhumka and Tim Watson.
 Trust Trackers for Computation Offloading in Edge-Based IoT Networks. In IEEE INFOCOM, 1–10. IEEE, 10–13 May 2021.

Generating the graphs requires scripts from: [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc)

# Reproducing Results

In order to reproduce the results, the setup instructions provided at [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc) should first be followed.

Then the test scripts in tests/run need to be edited to match the configuration used for these experiments. Six nodes were used, one configured as the root, two as edges and three as wsn nodes. The start script for edge needs to be edited differently on rr2 and rr6 to contain the correct configurations.

On rr2:
```bash
./tests/papers/infocom2021/edge-always-good.sh
```

On rr6 (always good):
```bash
./tests/papers/infocom2021/edge-always-good.sh
```

On rr6 (always bad):
```bash
./tests/papers/infocom2021/edge-always-bad.sh
```

On rr6 (unstable):
```bash
./tests/papers/infocom2021/edge-unstable.sh
```

# Generating Graphs and Tables

## Figure 2

```bash
./g.py
```

## Figure 3a and 4b

```bash
./analysis/graph/challenge_response_perf.py --lor-dir results/2020-08-09-pm-two-good
```

## Figure 4a and 4b

```bash
./analysis/graph/challenge_response_epoch.py --lor-dir results/2020-08-09-pm-two-good
```

## Figure 5a and 5b

```bash
./analysis/graph/challenge_response_epoch.py --lor-dir results/2020-08-09-pm-one-good-one-bad
```

## Figure 6a and 6b

```bash
./analysis/graph/challenge_response_epoch.py --lor-dir results/2020-08-10-pm3-one-good-one-unstable-1200
```

## Figure 6c

```bash
./analysis/graph/offloading_when_bad.py --lor-dir results/2020-08-10-pm3-one-good-one-unstable-1200
```

## Figure 6d

```bash
./analysis/graph/correctly_evaluated.py --lor-dir results/2020-08-10-pm3-one-good-one-unstable-1200
```

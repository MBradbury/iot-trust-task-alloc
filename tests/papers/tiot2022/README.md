# Introduction

These are the raw results that were used to present the results in:

 Matthew Bradbury, Arshad Jhumka, Tim Watson, Denys Flores, Jonathan Burton and Matthew Buttler.
 Threat Modelling Guided Trust-based Task Offloading in Resource-constrained Internet of Things Systems.

Generating the graphs requires scripts from: [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc)

# Reproducing Results

In order to reproduce the results, the setup instructions provided at [iot-trust-task-alloc](https://github.com/MBradbury/iot-trust-task-alloc) should first be followed.

Then the test scripts in tests/run need to be edited to match the configuration used for these experiements. Six nodes were used, one configured as the root, two as edges and three as wsn nodes.

## Profile

To build profile firmware for ECC Sign and Verify:
```bash
cd wsn/profile
make TARGET=zoul PLATFORM=remote-revb PROFILE_ECC=1
```

To build profile firmware for AES-CCM:
```bash
cd wsn/profile
make TARGET=zoul PLATFORM=remote-revb PROFILE_AES=1
```

## Two Good Edge nodes

Building and deploying:
```bash
./tests/papers/tiot2022/setup.sh
```

The start script for edge needs to be the same on both rr2 and rr6 to contain the correct configurations.

On both rr2 and rr6:
```bash
./tests/papers/tiot2022/edge-always-good.sh
```

## One Good Edge and One Bad Edge

The start script for edge needs to be edited differently on rr2 and rr6 to contain the correct configurations.

On rr2:
```bash
./tests/papers/tiot2022/edge-always-good.sh
```

On rr6:
```bash
./tests/papers/tiot2022/edge-always-bad.sh
```

## With DoS Adversary

```bash
./tests/papers/tiot2022/setup.sh
```

On wsn5 instead of running `tests/run/wsn.sh` run `tests/run/adversary.sh`.

```bash
./tests/papers/tiot2022/adversary-dos.sh
```

## With DoS Adversary and Small Buffer

```bash
./tests/papers/tiot2022/setup-small-buffer.sh
```

## With Aggressive Information Removal on unannounce/capability remove

```bash
./tests/papers/tiot2022/setup-aggressive-removal.sh
```

On rr6 with `capability remove`:
```bash
./tests/papers/tiot2022/edge-aggressive-capability-remove.sh
```

On rr6 with `unannounce`:
```bash
./tests/papers/tiot2022/edge-aggressive-unannounce.sh
```

## With Lazy Information Removal on unannounce

```bash
./tests/papers/tiot2022/setup-lazy-removal.sh
```

On rr6:
```bash
./tests/papers/tiot2022/edge-aggressive-unannounce.sh
```

# Generating Graphs and Tables

## Table 4

```bash
make -C wsn TRUST_MODEl=basic TRUST_CHOOSE=banded
./tools/binprof.py wsn/node/node.zoul
```

## Table 5

```bash
./analysis/parser/profile_pyterm.py --log-dir results/2020-08-28-profile
./analysis/parser/profile_pyterm.py --log-dir results/2020-09-01-profile-aes-ccm
```

## Figure 10

```bash
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-09-pm-dadspp-two-good --ax2-ymax 12
```

## Figure 11

```bash
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-09-pm-dadspp-one-good-one-bad --ax2-ymax 12
```

## Figure 12 and 13

```bash
./tools/regenerate_pcaps.py results/2021-02-09-pm-dadspp-two-good --timeout None
./analysis/graph/messages.py --log-dir results/2021-02-09-pm-dadspp-two-good --tx-ymax 140000 --rx-ymax 55000
```

## Figure 14 and 15

```bash
./tools/regenerate_pcaps.py results/2021-02-09-pm-dadspp-one-good-one-bad --timeout None
./analysis/graph/messages.py --log-dir results/2021-02-09-pm-dadspp-one-good-one-bad --tx-ymax 140000 --rx-ymax 55000
```

## Table 6

```bash
./analysis/parser/wsn_pyterm.py --log-dir results/2021-02-09-pm-dadspp-two-good
./analysis/parser/wsn_pyterm.py --log-dir results/2021-02-09-pm-dadspp-one-good-one-bad
./analysis/parser/wsn_pyterm.py --log-dir results/2021-02-09-am-dadspp-two-good-dcv
./analysis/parser/wsn_pyterm.py --log-dir results/2021-02-09-am-dadspp-two-good-dcv-small-ver-buf
```

## Figure 16 and 17

```bash
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-26-pm-capability-remove-attack-capability --ax2-ymax 20
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-26-pm-capability-remove-attack-server --ax2-ymax 20
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-26-pm-capability-remove-attack-server-lazy --ax2-ymax 20
```

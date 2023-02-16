# Evaluating Trustworthiness of Edge-Based Multi-Tenanted IoT Devices

Internet of Things (IoT) systems are expected to be deployed as solutions to problems in a wide variety of contexts, from building management, to smart city monitoring and to provide support to emergency services. However, many IoT devices are resource constrained and lack the capability or information to compute results for tasks that the IoT devices may be requested to perform. Instead these tasks will need to be offloaded to a server at the Edge of the network for a quick response. As these networks will have multiple organisations providing multiple IoT nodes and Edge nodes with different capabilities, the IoT devices need to know which Edge server they trust to return a timely response to a task.

This repository provides an implementation of such a system to facilitate trust-based task offloading. We provide two example applications and multiple example trust models.

The project was funded by [PETRAS](https://petras-iot.org/project/evaluating-trustworthiness-of-edge-based-multi-tenanted-iot-devices-team/), for more information see [here](https://mbradbury.github.io/projects/project-6-TEAM/).

This system architecture is described in: **Matthew Bradbury**, Arshad Jhumka, and Tim Watson. Trust Assessment in 32 KiB of RAM: Multi-application Trust-based Task Offloading for Resource-constrained IoT Nodes. In *The 36th ACM/SIGAPP Symposium on Applied Computing*, SAC'21, 1–10. Virtual Event, Republic of Korea, 22–26 March 2021. ACM. [doi:10.1145/3412841.3441898](https://doi.org/10.1145/3412841.3441898). [[bibtex](https://github.com/MBradbury/publications/raw/master/bibtex/Bradbury_2021_TrustAssessment32.bib)] [[file](https://github.com/MBradbury/publications/raw/master/papers/SAC-DADS2021.pdf)] [[dataset](https://doi.org/10.5281/zenodo.4312801)].

A more detailed look at the architecture and threats to it is described in: **Matthew Bradbury**, Arshad Jhumka, Tim Watson, Denys Flores, Jonathan Burton, and Matthew Butler. Threat-Modeling-Guided Trust-Based Task Offloading for Resource-Constrained Internet of Things. *ACM Transactions on Sensor Networks*, 18(2):41, 2022. [doi:10.1145/3510424](https://doi.org/10.1145/3510424). [[bibtex](https://github.com/MBradbury/publications/raw/master/bibtex/Bradbury_2022_ThreatModellingGuided.bib)] [[file](https://github.com/MBradbury/publications/raw/master/papers/TOSN2022.pdf)] [[dataset](https://doi.org/10.5281/zenodo.4568700)].

## Repository Structure

This repository is structured as follows, with the most important implementation being in:

 - The implementation of firmware for IoT and Edge nodes is contained in [/wsn/node](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/wsn/node) and [/wsn/edge](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/wsn/edge) respectively.
 - The implementation of two example resource-rich applications and the root node application is contained in [/resource_rich](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/resource_rich).

Other directories contain supporting code:

 - The [/tools](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/tools) and [/tests/run](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/tests/run) directories contains various tools in order to setup and run experiments
 - The [/analysis](https://github.com/MBradbury/iot-trust-task-alloc/tree/master/analysis) directory contains scripts to analyse and graph results from experiments

# Setup

This system assumes the use of [Zolertia RE-Mote rev.b](https://zolertia.io/product/re-mote/) or [nRF52840](https://www.nordicsemi.com/Products/nRF52840) hardware for IoT deployments. Parts of the implementation depend on the hardware accelerated cryptographic operations they provide.

## Development

1. Install dependencies

```bash
sudo apt-get install git build-essential gcc-arm-none-eabi python3 texlive-extra-utils cm-super texlive-latex-extra dvipng poppler-utils srecord rsync ansible
python3 -m pip install pexpect cbor2
```

2. Download Contiki-NG

```bash
mkdir ~/wsn
cd ~/wsn
git clone -b petras https://github.com/MBradbury/contiki-ng.git
cd contiki-ng
git submodule update --init
```

Edit `~/.bashrc` to add the path to Contiki-NG before the interactivity check:
```bash
export CONTIKING_OSCORE_DIR="~/wsn/contiki-ng"
export COOJA_DIR="$CONTIKING_OSCORE_DIR/tools/cooja"
```

Please note that any time you see a `~` you may need to replace with the path to your home directory. This can be obtained via `realpath ~`.

In order for builds to succeed you will need to modify `os/net/security/tinydtls/sha2/sha2.c` by commenting out line 35 (`#include "tinydtls.h"`).

3. Setting up building for nRF52840

The [nRF52840 SDK](https://www.nordicsemi.com/Products/Development-software/nRF5-SDK/Download) included with Contiki-NG does not contain all the appropriate headers, source files and libraries to be able to compile code that depends on CryptoCell. So you will need to download and overwrite the nRF52 SDK submodule.

The SDK is located in: `~/wsn/contiki-ng/arch/cpu/nrf52840/lib/nrf52-sdk`

```bash
cd ~/wsn/contiki-ng/arch/cpu/nrf52840/lib/
mv nrf52-sdk nrf52-sdk-original
wget https://www.nordicsemi.com/-/media/Software-and-other-downloads/SDKs/nRF5/Binaries/nRF5_SDK_17.1.0_ddde560.zip
unzip nRF5_SDK_17.1.0_ddde560.zip -d nrf52-sdk
cd nrf52-sdk
mv nRF5_SDK_17.1.0_ddde560/* .
rmdir nRF5_SDK_17.1.0_ddde560/
```

4. Clone this repository

```bash
cd ~/wsn
git clone https://github.com/MBradbury/iot-trust-task-alloc.git
cd iot-trust-task-alloc && git submodule update --init
```

5. Install Wireshark

Please instead install Wireshark 3.4 or later to be able to analyse OSCORE packets.
```bash
sudo apt install wireshark
```

Check that the version is later than 3.4
```bash
wireshark --version
```

6. Install pyshark

Install pyshark version 0.4.3 or greater
```bash
python3 -m pip install --upgrade pyshark>=0.4.3
```

## Using Wireshark

In order for wireshark to decrypt OSCORE projected packets you will need to provide details on the OSCORE security contexts to Wireshark. OSCORE is only supported on unreleased versions of Wireshark (as of writing this), hence the need to install Wireshark from source.

To setup OSCORE contexts in Wireshark please do the following:
1. Select `Edit`
2. Select `Preferences`
3. Expand `Protocols` and select `OSCORE`
4. Click on `Edit` in order to enter security contexts

The OSCORE contexts will be generated by `analysis/parser/pyshark_pcap.py` in a file called `oscore.contexts.uat`.

## Install Dependencies for Root, WSN and Edge Observers

```bash
ansible-playbook playbooks/observer-setup.yaml --ask-become-pass
```

Please note that mosquitto needs to be version 1.6 or later as MQTT v5 support is required.

## Install Dependencies for Root Observers

```bash
ansible-playbook playbooks/setup-root.yaml
```

## nRf52840 Configuration

If using nRF52840s you will need to appropriately configure them. Without this [you will not be able to use these devices](https://mbradbury.github.io/blog/2022-02-18-challenges-porting-to-the-nrf52840).

```bash
ansible-playbook playbooks/configure-nrf.yaml
```

# Instructions to Deploy

For simplicity a number of test scripts have been written to aid in simplifying running experiments. These test scripts should be preferred instead of running tests manually, unless the additional flexibility is required.

You should edit these bash scripts in order to configure the parameters passed to the runner scripts they call. For example, on the Edge node you might want to set the routing application to behave badly instead of the default correct behaviour.

```bash
#nohup python3 -m tools.run.edge --application monitoring 2 --application routing 0 --application challenge_response 1 &
nohup python3 -m tools.run.edge --application monitoring 2 --application bad_routing 0 " --duration inf --approach random" --application challenge_response 1 &
```

1. Specify the configuration

You will need to create a file that details the configuration of your tests. A default file exists at `common/configuration.py.example` that can be copied to `common/configuration.py` and edited. In this example file there are six devices deployed with `wsn1` acting as the root, `wsn2` and `wsn6` acting as edge nodes, and the remaining devices acting as IoT nodes.

The `hostname_to_ips` variable specifies a mapping from hostnames (which needs to be configured on the linux machines acting as observers) and the IPv6 addresses of the attached IoT devices. The root IPv6 address is set to fd00::1 and is hardcoded in `tools/run/root.py`. The other IPv6 addresses can be found in a number of ways. One approach is to follow the Contiki-NG [tutorial to ping devices](https://github.com/contiki-ng/contiki-ng/wiki/Tutorial:-IPv6-ping). Alternatively when flashing firmware the 'Primary IEEE Address' of a device will be shown similarly to the example below. This can be converted into IPv6 address by: (1) removing the colons, (2) replacing the leading 00 with 2, (3) adding fd00:: before the 2, and finally (4) adding colons every four hex characters from the right. So `00:12:4B:00:14:D5:2B:D6` becomes `fd00::212:4B00:14D5:2BD6`.

```
Opening port /dev/ttyUSB0, baud 460800
Reading data from edge.bin
Cannot auto-detect firmware filetype: Assuming .bin
Connecting to target...
CC2538 PG2.0: 512KB Flash, 32KB SRAM, CCFG at 0x0027FFD4
Primary IEEE Address: 00:12:4B:00:14:D5:2B:D6
Erasing 524288 bytes starting at address 0x00200000
    Erase done
Writing 516096 bytes starting at address 0x00202000
```

The `root_node` variable specifies which observer will run the root node, `device_stereotypes` specify the stereotype tags that should be included in the certificates of the different entities, and `hostname_to_names` defines alternate names that will be included in generated graphs.

2. Build

First, edit `~/wsn/iot-trust-task-alloc/common/configuration.py` to specify the nodes used in the network.

```bash
cd ~/wsn/iot-trust-task-alloc
python3 -m tools.setup <trust-model> <trust-choose> --deploy ansible
```

`tools.setup` will deploy to observers as per your ansible configuration.

You should refer to the help command for information on the parameters that can be provided to setup.

```bash
python3 -m tools.setup --help
```

3. On Root

```bash
cd ~/deploy/iot-trust-task-alloc
./tests/run/root.sh
```

4. On Observer for Sensor Nodes

```bash
cd ~/deploy/iot-trust-task-alloc
./tests/run/wsn.sh
```

5. On Edges

```bash
cd ~/deploy/iot-trust-task-alloc
./tests/run/edge.sh
```

# Introductions to deploy (Ansible)

The recommended way to deploy is to use an Ansible playbook to run appropriate scripts on the observers.

See `tests/scenarios` for example ways to configure an experiment.

For example to run the `all-good` scenario, you would:

1. Setup and Deploy

```bash
./tests/scenarios/all-good/setup.sh
```

2. Start the experiment

```bash
ansible-playbook tests/scenarios/all-good/run.yaml
```

3. Stop the experiment

After some time you can stop the experiment like so:
```bash
ansible-playbook playbooks/stop-experiments.yaml
```

# Instructions to analyse results

## Obtaining Results

In order to fetch results from the devices run:
```bash
ansible-playbook playbooks/fetch-results.yaml
```

You can specify the folder to store the results in via:
```bash
ansible-playbook playbooks/fetch-results.yaml --extra-vars "destination=<folder>"
```

## Generate pcap

If the binaries were compiled with `--with-pcap` then there will be a `*.packet.log` file for each device. This now needs to be converted to a pcap file.

pcaps can either be converted individually using `./tools/regenerate_pcap.py` or processed for all packet logs in a directory using `./tools/regenerate_pcaps.py`. When a large number of packets have been collected, it will be necessary to disable the timeout with `--timeout None`.

Individually:
```bash
./tools/regenerate_pcap.py results/2021-02-03-am-dadspp-one-good-one-bad/edge.wsn6.packet.log --timeout None
```

Batch:
```bash
./tools/regenerate_pcaps.py results/2021-02-03-am-dadspp-one-good-one-bad/ --timeout None
```

Once pcaps have been generated Wireshark can be used to view them via:
```bash
wireshark -o:oscore.contexts=results/2021-02-03-am-dadspp-one-good-one-bad/keystore/oscore.contexts.uat results/2021-02-03-am-dadspp-one-good-one-bad/edge.wsn6.packet.log.pcap
```

## Graphing Results

There are a variety of tools to graph the results

### Graphing Messages Sent and Received

To graph the number of bytes sent and received, use the following:
```bash
./analysis/graph/messages.py --log-dir results/2021-02-03-pm-dadspp-one-good-one-bad/
```
This tool will categorise the messages.

### Trust Choose Over Time

To graph trust ranking and to whom tasks were sent over time, use the following:
```bash
./analysis/graph/trust_choose_evolution.py --log-dir results/2021-02-03-pm-dadspp-one-good-one-bad/
```

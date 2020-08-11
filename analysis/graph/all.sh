#!/bin/bash

./analysis/graph/challenge_response_epoch.py --log-dir results/*
./analysis/graph/challenge_response_perf.py --log-dir results/*
./analysis/graph/correctly_evaluated.py --log-dir results/*
./analysis/graph/offloading_when_bad.py --log-dir results/*

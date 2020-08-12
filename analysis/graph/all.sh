#!/bin/bash

for d in results/*
do
    echo $d/graph
    rm -rf "$d/graph"
done

./analysis/graph/challenge_response_epoch.py --log-dir results/*
./analysis/graph/challenge_response_perf.py --log-dir results/*
./analysis/graph/correctly_evaluated.py --log-dir results/*
./analysis/graph/offloading_when_bad.py --log-dir results/*

#!/bin/bash

honggfuzz \
    --run_time 10 \
    -Q \
    -n 1 \
    -f input/ \
    -l fuzzing.log \
    -- ./md2_dgst ___FILE___ 2>&1 | \
    analyzer collect \
    -r fuzzing.log \
    -o results.json \
    -b ./md2_dgst


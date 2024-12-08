#!/bin/bash

/home/linuxbrew/.linuxbrew/Cellar/gnu-time/1.9/bin/time -v /workspace/myklee/klee/build/bin/klee \
  -check-div-zero=false \
  -check-overshift=false \
  --search=randomsp \
  -max-instruction-time=60 \
  -max-solver-time=60 \
  -enable-speculative \
  -speculative-order=1 \
  -max-sew=200 \
  test.bc

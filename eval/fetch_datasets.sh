#!/usr/bin/env bash
# Download the public benchmarks used by the evaluation into eval/.data/
# Pinned to the commits/versions the published results were produced with.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .data && cd .data
[ -d InjecAgent ] || git clone -q https://github.com/uiuc-kang-lab/InjecAgent
[ -d R-Judge ] || git clone -q https://github.com/Lordog/R-Judge
pip install -q "agentdojo==0.1.35"
for d in InjecAgent R-Judge; do echo "$d $(git -C $d rev-parse --short HEAD)"; done

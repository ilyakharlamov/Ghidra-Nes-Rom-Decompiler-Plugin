#!/bin/sh
docker run -it \
  --mount type=bind,source=$(pwd),target=/mnt \
  --mount type=bind,source="$(echo ~/.ghidra/)",target=/tilda_dot_ghidra \
  --mount type=bind,source=/Applications,target=/Applications \
  ghidra:run /bin/bash

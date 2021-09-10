#!/bin/sh
docker run -it --mount type=bind,source=$(pwd),target=/mnt --mount type=bind,source=/Applications,target=/Applications gradle:7.2.0-jdk11 /bin/bash

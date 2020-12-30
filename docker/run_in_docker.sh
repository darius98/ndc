#!/usr/bin/env bash

set -e

BUILD_DIR=build/docker_${NDC_IMAGE_NAME}
cmake -DCMAKE_BUILD_TYPE=Debug -H. -B${BUILD_DIR} -G Ninja
ninja -C ${BUILD_DIR} -j 4

${BUILD_DIR}/ndc

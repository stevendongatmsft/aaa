#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# This script builds all binaries

mkdir -p bin
pushd bin
echo building aasp
# TODO: use 'upx --best --lzma' to reudce executable size
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" github.com/container-investigations/aaa/cmd/aasp
popd

echo building get-snp-report
git clone https://github.com/microsoft/confidential-sidecar-containers.git
make -C confidential-sidecar-containers/tools/get-snp-report
cp confidential-sidecar-containers/tools/get-snp-report/bin/get-snp-report ./bin
rm -rf confidential-sidecar-containers

echo building containers
docker build -t aasp -f docker/Dockerfile.aasp .
docker build -t aasp_sample -f docker/Dockerfile.sample .

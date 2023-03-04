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

echo generating wrapped secret
pushd examples/secret_provisioning
../../bin/aasp --infile plaintext --outfile wrapped --keypath testkey000
popd

echo building get-snp-report
git clone https://github.com/microsoft/confidential-sidecar-containers.git
make -C confidential-sidecar-containers/tools/get-snp-report
cp confidential-sidecar-containers/tools/get-snp-report/bin/get-snp-report ./bin
rm -rf confidential-sidecar-containers

echo building containers
docker build -t aasp -f docker/Dockerfile.aasp .
docker build -t aasp_sample -f docker/Dockerfile.sample .
docker build -t encrypted_sample -f docker/Dockerfile.enc .

echo encrypting container image and pushing to the registry
bin/aasp &
OCICRYPT_KEYPROVIDER_CONFIG=examples/encrypted_image/ocicrypt.conf skopeo copy --insecure-policy --encryption-key provider:attestation-agent:aasp:imagekey000 docker-daemon:encrypted_sample:latest docker://jxyang100/encrypted_sample_imagekey000
pkill aasp

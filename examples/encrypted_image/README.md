# How to encrypt a container image and run it in a confidential pod using AASP

This example shows how to encrypt a container image using a key stored in MHSM,
and run the container in a confidential pod using Kata-CC. Even though both the
encryption and decryption processes by other tools, [skopeo](https://github.com/containers/skopeo)
in the case of encryption, and [image-rs](https://github.com/confidential-containers/image-rs)
in the case of decryption, the actual key provisioning are backed by AASP in both cases.

## Set up MHSM

The same as the [secret provisioning example](../secret_provisioning#set-up-mhsm).

## Set up an asymmetric key in MHSM with a key release policy

The same as the [secret provisioning example](../secret_provisioning#set-up-an-asymmetric-key-in-mhsm-with-a-key-release-policy).

## Encrypt a container image with the asymmetric key

The same process as described [here](https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#image-encryption) and [here](https://medium.com/@lumjjb/encrypting-container-images-with-skopeo-f733afb1aed4).
Specifically we use AASP as a key provider as show in the [script](../../buildall.sh):

1. First we build a local container image;
1. We run "aasp" as a GRPC service, and reference the service in [OCICRYPT_KEYPROVIDER_CONFIG](ocicrypt.conf);
1. We encrypt the container image with `skopeo` and the option `provider:attestation-agent:aasp:imagekey000` where `imagekey000` is established in the above step. In this example we encrypted all layers of the image.
It's possible to encrypt only certain layers that contain secret with the `skopeo` option `--encrypt-layer`;
1. Finally we push the encrypted container image to a container registry.

## Verify that the container image is not runnable outside a TEE

If we run the encrypted container image directly with docker, we should see an error message like:

> docker: failed to register layer: ApplyLayer exit status 1 stdout:  stderr: archive/tar: invalid tar header.

## Verify that the container image is runnable inside a TEE with Kata-CC and AASP

Certain conditions must be met before the encrypted container can be decrypted
with the key stored in MHSM:

* The container must be running in a confidential pod protected by SEV-SNP or TDX
* Kata-CC stack is used to create the pod
* Both tools **aasp** and **skopeo** must be included in the guest image at path **/bin/**
* **aasp** is running when the image decryption process starts
* The measurements of both the guest OS and the workload containers must meet the
conditions specified in Key Release Policy above.

Note: the latest Kata-CC has removed support for skopeo in kata-agent,
and relies on image-rs as the only choice for image decryption.
Additional work might be required for integrating AASP with image-rs.

No changes are required in the yaml file for a Kubernetes deployment except
for pointing to the encrypted container image and specifying **kata** as the
runtime class. Please see [this](https://github.com/container-investigations/kata-verity/blob/kata-cc-based/katacc-bootstrap/encrypted-sample.yaml) as an example.





# Azure Attestation and Secret Provisioning service (AASP)

AASP is a GRPC service for provisioning secrets into confidential containers
running inside a trusted execution environment (TEE). It also provides
attestation related APIs through GRPC.

## Types of secrets protected

A secret could be a symmetric/asymmetric key for decrypting/communicating
sensitive data, or the sensitive data themselves. When the sensitive data
size is large, it's recommended to encrypt the data with a randomly
generated symmetric key, and protect the key with AASP.

## Dependent services and Trusted Computing Base (TCB)

Currently AASP depends on [Microsoft Azure Attestation service](https://azure.microsoft.com/en-us/products/azure-attestation) (MAA) and
[Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview)
(MHSM) for secret provisioning. As such,
MAA and MHSM are included in the TCB for secret provisioning. If users
prefer a smaller TCB or customized attestation service and/or Key Management
System (KMS), they should rely on the attestation API of AASP solely.

# Supported platforms

Currently AASP works on AMD processors with [SEV-SNP](https://www.amd.com/en/processors/amd-secure-encrypted-virtualization)
enabled and a Linux kernel that is SEV-SNP enlightened.

# Building and installation

Use `buildall.sh` to build the `AASP` tool and container.

# Instructions

The [example](examples/secret_provisioning/README.md) provides an end-to-end workflow on how to
protect a secret with the tool and how to provision the secret in a container
running alongside the AASP container in a Kubernetes pod that is VM-isolated
based on [Kata containers](https://github.com/kata-containers/kata-containers).

# Credits

This project heavily relies on [Confidential Sidecar Containers](https://github.com/microsoft/confidential-sidecar-containers)
for their implementation of Secure Key Release (SKR)

# Compatibility

AASP conforms to the [keyprovider protocol](
https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md) of ocicrypt and [Kata Attestation Agent]
(https://github.com/confidential-containers/attestation-agent)

# Licensing

This project is released under the [MIT License](LICENSE.txt).

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

# Code of conduct

This project has adopted the
[Microsoft Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
All participants are expected to abide by these basic tenets to ensure that the
community is a welcoming place for everyone.



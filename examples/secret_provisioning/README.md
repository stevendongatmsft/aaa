# Set up MHSM

To set up a MHSM instance, follow instructions [here with Azure CLI](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli),
or through the [Azure portal](https://ms.portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2FmanagedHSMs).

You can follow the installation instructions for Azure CLI [here](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli).

# Set up an asymmetric key in MHSM with a key release policy

## Prepare for the key release policy
```bash
# Create a managed identity for accessing MHSM. Note the Principle ID of the identity
az identity create -g <resource-group-name> -n <identity-name>
export MANAGED_IDENTITY=<principle-id>
# Choose a MAA instance for the attestation service, e.g. e.g. sharedeus2.eus2.attest.azure.net
export MAA_ENDPOINT=<maa-endpoint>
# Specify a trusted measurement for Kata guest image
export GUEST_IMAGE_MEASUREMENT=<sevsnp-vm-launch-measurement>
# Specify a trusted measurement for the containers running in a confidential pod
export WORKLOAD_MEASUREMENT=<hash-of-security-policy-for-confidential-pod>
```

Even though `GUEST_IMAGE_MEASUREMENT` and `WORKLOAD_MEASUREMENT` are optional,
we strongly recommend them to be included in the key release policy for
better protection of the MHSM key which in turn protects your secrets.

## Create an asymmetric key in MHSM and produce files related to the key

This is a one time effort. Once the key is created, it can be used to protect
as many secrets as possible.

Run [scripts/setup-key-mhsm.sh](https://github.com/container-investigations/aaa/blob/master/scripts/setup-key-mhsm.sh)
with a given key name and MHSM instance name. When successful,it produces
several files:

* A key release policy file
* The public key of the created asymmetric key
* A key info file that associates the key with the chosen MAA and MHSM endpoints

The script also assigns `read` permission to the managed identity for the key.

# Protect secrets with the asymmetric key

In this example, the secret is stored in file [plaintext](plaintext). Assuming
the name of the key we created in the above step is `testkey000`, we can
protect the secret with (adjust the path to the key if necessary):

```bash
aasp --infile plaintext --keypath ./testkey000 --outfile wrapped
```

# Copy the wrapped secret into a container where it will be unwrapped inside a TEE

This [sample docker file](https://github.com/container-investigations/aaa/blob/master/docker/Dockerfile.sample)
shows how the secret is unwrapped with the script [unwrap.sh](https://github.com/container-investigations/aaa/blob/master/scripts/unwrap.sh).
From this point, the secret is made available to the confidential container as
a plaintext file, and the container can use it for further confidential computing.

Check [here](https://github.com/container-investigations/kata-verity/tree/kata-cc-based/katacc-bootstrap#deploy-a-sample-secret-provisioning-pod)
fora sample deployment of a confidential pod with the AASP container,
a container that invokes the attetation API, and a container that invokes
the secret provisioning API of the AASP container.





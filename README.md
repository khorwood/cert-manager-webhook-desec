<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# deSEC webhook for cert-manager

A [cert-manager](https://cert-manager.io/docs/installation/kubernetes/) ACME DNS01 solver webhook for [deSEC](https://desec.io/).

## Prerequisites

A Kubernetes cluster with cert-manager deployed. If you haven't already installed cert-manger, follow the guide here.

## Deployment

### Using Helm

```
groupName: acme.khorwood.github.io
image:
  repository: ghcr.io/khorwood/cert-manager-webhook-desec
  tag: 1.0.0
```

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. DESEC_TOKEN=abc123 make test
```

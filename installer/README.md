**\[DEPRECATED\]**

The Google Cloud Platform (GCP) Service Broker is being deprecated in favour of [GCP Config Connector](https://github.com/GoogleCloudPlatform/k8s-config-connector).

# Service Catalog Installer

Service Catalog Installer is a CLI tool to manage Service Catalog and Google
Cloud Platform Service Broker atop Kubernetes Cluster.

- [Intro](#intro)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Build](#build)
- [Basic Tutorial](#tutorial)
- [Contribution](#contribution)

## Intro

Service Catalog Installer `sc` lets you do the following:

- Install Service Catalog
- Uninstall Service Catalog
- Install a Service Broker
- Uninstall a Service Broker

## Requirements

Before installing Service Catalog atop Kubernetes cluster, you need to ensure following requirements are met.

- [cfssl](https://github.com/cloudflare/cfssl) tools are needed for generating SSL artifacts. Install `cfssl` using following command
  ```bash
  go get -u github.com/cloudflare/cfssl/cmd/...
  which cfssl
  /home/sunil/go/bin/cfssl
  which cfssljson
  /home/sunil/go/bin/cfssljson
  ```
- Service Catalog requires Kubernetes version 1.7 onwards.
- Kubectl installed and configured to connect to a Kubernetes v1.7+ cluster.
- Kubectl user should have cluster-admin role to be able to install Service Catalog. Run following command to ensure that:
  ```bash
  kubectl create clusterrolebinding cluster-admin-binding --clusterrole=cluster-admin --user=<user-name>
  ```
- [gcloud](https://cloud.google.com/sdk/) should be installed and configured with following
   commands in order to be used by the `sc` to configure the Service Broker.
  ```bash
  gcloud components install beta
  gcloud auth login
  gcloud auth application-default login
  ```

## Installation

`sc` is written in Go and can be installed using `go get`.

```Go
go get -u github.com/GoogleCloudPlatform/k8s-service-catalog/installer/cmd/sc
```

After running the above command, `sc` should get installed in your GOPATH/bin dir.

## Usage

- To print usage instructions, run
  ```bash
  sc --help
  ```
- To check if all the dependencies are installed, run
  ```bash
  sc check
  Dependency check passed. You are good to go.
  ```
- To install Service Catalog in Kubernetes cluster, run install help. If you are running on a non-GCP environment, specify the storageclass that you want to use for the backup.
  ```bash
  sc install --help
  installs Service Catalog in Kubernetes cluster.
  assumes kubectl is configured to connect to the Kubernetes cluster.

  Usage:
    sc install [flags]

  Flags:
        --etcd-backup-storageclass string   Etcd Backup StorageClass (default "standard")
        --etcd-cluster-size int32           Etcd cluster size (default 3)
    -h, --help                              help for install

  Global Flags:
        --alsologtostderr                  log to standard error as well as files
        --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
        --log_dir string                   If non-empty, write log files in this directory
        --logtostderr                      log to standard error instead of files
        --stderrthreshold severity         logs at or above this threshold go to stderr (default 2)
    -v, --v Level                          log level for V logs
        --vmodule moduleSpec               comma-separated list of pattern=N settings for file-filtered logging
  ```

- To uninstall Service Catalog in Kubernetes cluster, run
  ```bash
  sc uninstall
  ```
- To add the GCP Service Broker to the Service Catalog, run
  ```bash
  sc add-gcp-broker
  ```
- To remove the GCP Service Broker from the Service Catalog, run
  ```bash
  sc remove-gcp-broker
  ```

## Build

If you want to build the installer yourself, here are the instructions to do so.

```bash
# Install [Go Dep](https://github.com/golang/dep) for dependency management using `go get`
go get -u github.com/golang/dep/cmd/dep

# Install `go-bindata` using `go get`
go get -u github.com/jteeuwen/go-bindata/...

# To build `sc` binary, run
make
# You should `sc` binary created in output/bin directory.
```

## Tutorial

Once you have Service Catalog installed and the Service Broker added to the cluster,
follow this [basic tutorial](/installer/service-catalog-pubsub-tutorial.md) to get started with Service Catalog.

## Contribution

We are always looking for contributors, so if you want to contribute to the installer codebase, please follow the [workflow instructions](/installer/github-workflow.md).

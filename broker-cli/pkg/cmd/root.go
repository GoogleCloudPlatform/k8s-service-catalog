// Copyright © 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cmd contains all the commands in broker-cli
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/auth"
	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/client/adapter"
	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/cmd/flags"
	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands.
var (
	RootCmd = &cobra.Command{
		Use:   "broker-cli",
		Short: "Service Broker Client CLI",
		Long: "broker-cli is the client CLI for Service Broker.\n" +
			"This application is a tool to call Service Broker\n" +
			"APIs directly.",
	}

	// Values that are set from flags.
	credsFlag string
)

func init() {
	flags.StringFlag(RootCmd.PersistentFlags(), &credsFlag, "creds", "c", "[Optional] Private, json key file to use for authenticating requests. If not specified, we use gcloud authentication.")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// httpAdapterFromFlag returns an http adapter with credentials to gcloud if
// credsFlag is not set and to a service account if it is set.
func httpAdapterFromFlag() *adapter.HttpAdapter {
	var client *http.Client
	var err error
	ctx := context.Background()
	if credsFlag != "" {
		client, err = auth.HttpClientFromFile(ctx, credsFlag)
		if err != nil {
			log.Fatalf("Error creating http client from service account file %s: %v", credsFlag, err)
		}
	} else {
		client, err = auth.HttpClientWithDefaultCredentials(ctx)
		if err != nil {
			log.Fatalf("Error creating http client using gcloud credentials: %v", err)
		}
	}
	return adapter.NewHttpAdapter(client)
}

func parseStringToObjectMap(s string) map[string]interface{} {
	if s == "" {
		return nil
	}

	var objMap map[string]interface{}
	err := json.Unmarshal([]byte(s), &objMap)
	if err != nil {
		log.Fatalf("Error unmarshalling string %q to object map: %v\n", s, err)
	}

	return objMap
}

func waitOnOperation(opID string, opType adapter.OperationType, client adapter.Adapter,
	pollOperation func(string, adapter.OperationType, adapter.Adapter) (*adapter.Operation, error)) (*adapter.Operation, error) {
	baseDelay := 100 * time.Millisecond
	maxDelay := 6 * time.Second
	retries := 0

	curState := adapter.OperationInProgress
	var op *adapter.Operation
	var err error
	for curState == adapter.OperationInProgress {
		delay := time.Duration(math.Pow(2, float64(retries)) * float64(baseDelay))
		if delay > maxDelay {
			delay = maxDelay
		}
		time.Sleep(delay)

		op, err = pollOperation(opID, opType, client)
		if err != nil {
			return nil, fmt.Errorf("error polling last operation %q: %v\n", opID, err)
		}

		curState = op.State
		retries++
	}

	// Operation states other than "in progress" are all considered as end states.
	return op, nil
}

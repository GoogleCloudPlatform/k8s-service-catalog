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

package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/client/adapter"
	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/cmd/flags"
	"github.com/spf13/cobra"
)

var (
	catalogFlags struct {
		flags.BrokerURLConstructor
		apiVersion string
	}
	// catalogCmd represents the catalogs command.
	catalogCmd = &cobra.Command{
		Use:   "catalog",
		Short: "Get broker catalog",
		Long:  "Get broker catalog",
		Run: func(cmd *cobra.Command, args []string) {
			client := httpAdapterFromFlag()
			res, err := client.GetCatalog(&adapter.GetCatalogParams{
				APIVersion: catalogFlags.apiVersion,
				Server:     catalogFlags.BrokerURL(),
			})
			if err != nil {
				log.Fatalf("Error getting catalog: %v\n", err)
			}

			marshalledRes, err := json.MarshalIndent(res, "", "    ")
			if err != nil {
				log.Fatalf("Error marshalling result\nResult: %+v\nError: %v", res, err)
			}
			fmt.Println(string(marshalledRes))
		},
	}
)

func init() {
	flags.StringFlag(catalogCmd.PersistentFlags(), &catalogFlags.Server, flags.ServerLongName, flags.ServerShortName, fmt.Sprintf("[Required if %s and %s are not given] Broker URL to make request to (https://...).", flags.ProjectLongName, flags.BrokerLongName))
	flags.StringFlag(catalogCmd.PersistentFlags(), &catalogFlags.Project, flags.ProjectLongName, flags.ProjectShortName, fmt.Sprintf("[Required if %s is not given] the GCP project of the broker", flags.ServerLongName))
	flags.StringFlag(catalogCmd.PersistentFlags(), &catalogFlags.Broker, flags.BrokerLongName, flags.BrokerShortName, fmt.Sprintf("[Required if %s is not given] the broker name", flags.ServerLongName))
	flags.StringFlagWithDefault(catalogCmd.PersistentFlags(), &catalogFlags.apiVersion, flags.ApiVersionLongName, flags.ApiVersionShortName, flags.ApiVersionDefault,
		flags.ApiVersionDescription)

	// Host is the hostname to use for Service Broker API calls. There's no help message here since it's a hidden flag.
	catalogCmd.PersistentFlags().StringVar(&catalogFlags.Host, flags.HostLongName, flags.HostBrokerDefault, "")
	catalogCmd.PersistentFlags().MarkHidden(flags.HostLongName)

	RootCmd.AddCommand(catalogCmd)
}

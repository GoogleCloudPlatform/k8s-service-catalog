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
	brokersFlags struct {
		catalogs []string
		broker   string
		host     string
		project  string
		title    string
	}

	// brokersCmd represents the brokers command.
	brokersCmd = &cobra.Command{
		Use:   "brokers",
		Short: "Manage service brokers",
		Long:  "Manage service brokers",
	}

	// brokersGetCmd represents the brokers create command.
	brokersCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a service broker",
		Long:  "Create a service broker",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&brokersFlags.project, &brokersFlags.broker, &brokersFlags.catalogs)

			// Title defaults to name if not present.
			title := brokersFlags.title
			if title == "" {
				title = brokersFlags.broker
			}

			http := httpAdapterFromFlag()
			res, err := http.CreateBroker(&adapter.CreateBrokerParams{
				RegistryURL: brokersFlags.host,
				Project:     brokersFlags.project,
				Name:        brokersFlags.broker,
				Title:       title,
				Catalogs:    brokersFlags.catalogs,
			})
			processResult(res, err)
		},
	}

	// brokersDeleteCmd represents the brokers delete command.
	brokersDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete a service broker",
		Long:  "Delete a service broker",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&brokersFlags.project, &brokersFlags.broker)

			http := httpAdapterFromFlag()
			params := &adapter.DeleteBrokerParams{
				RegistryURL: brokersFlags.host,
				Project:     brokersFlags.project,
				Name:        brokersFlags.broker,
			}
			err := http.DeleteBroker(params)
			processResult(nil, err)
		},
	}

	// brokersGetCmd represents the brokers get command.
	brokersGetCmd = &cobra.Command{
		Use:   "get",
		Short: "Get a service broker",
		Long:  "Get a service broker",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&brokersFlags.project, &brokersFlags.broker)

			http := httpAdapterFromFlag()
			res, err := http.GetBroker(&adapter.GetBrokerParams{
				RegistryURL: brokersFlags.host,
				Project:     brokersFlags.project,
				Name:        brokersFlags.broker,
			})
			processResult(res, err)
		},
	}

	// brokersListCmd represents the brokers list command.
	brokersListCmd = &cobra.Command{
		Use:   "list",
		Short: "List service brokers for a project",
		Long:  "List service brokers for a project",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&brokersFlags.project)

			http := httpAdapterFromFlag()
			res, err := http.ListBrokers(&adapter.ListBrokersParams{
				RegistryURL: brokersFlags.host,
				Project:     brokersFlags.project})
			processResult(res, err)
		},
	}
)

func init() {
	// Flags for all brokers subcommands.
	flags.StringFlag(brokersCmd.PersistentFlags(), &brokersFlags.project, flags.ProjectLongName, flags.ProjectShortName, "[Required] The GCP Project to use.")
	// This is defined here instead of in root so that we can define an appropriate default.
	// Host is the hostname to use for Service Registry API calls. There's no help message here since it's a hidden flag.
	brokersCmd.PersistentFlags().StringVar(&brokersFlags.host, flags.HostLongName, "https://serviceregistry.googleapis.com", "")
	brokersCmd.PersistentFlags().MarkHidden(flags.HostLongName)

	// Flags for brokers create.
	flags.StringFlag(brokersCreateCmd.PersistentFlags(), &brokersFlags.broker, flags.BrokerLongName, flags.BrokerShortName, "[Required] Name of broker to create.")
	flags.StringFlag(brokersCreateCmd.PersistentFlags(), &brokersFlags.title, "title", "t", "[Optional] Title of broker to create. Defaults to broker name")
	// TODO(richardfung): can we make this more user friendly by not forcing them to specify projects/...?
	// TODO(richardfung): what should the short flag actually be here?
	flags.StringArrayFlag(brokersCreateCmd.PersistentFlags(), &brokersFlags.catalogs, "catalog", "g", "[Required] Catalogs for broker to use. Should be of the form \"projects/<project>/catalogs/<catalog>\".")

	// Flags for brokers delete.
	flags.StringFlag(brokersDeleteCmd.PersistentFlags(), &brokersFlags.broker, flags.BrokerLongName, flags.BrokerShortName, "[Required] The name of the broker.")

	// Flags for brokers get.
	flags.StringFlag(brokersGetCmd.PersistentFlags(), &brokersFlags.broker, flags.BrokerLongName, flags.BrokerShortName, "[Required] The name of the broker.")

	RootCmd.AddCommand(brokersCmd)
	brokersCmd.AddCommand(brokersCreateCmd, brokersDeleteCmd, brokersGetCmd, brokersListCmd)
}

func processResult(result interface{}, err error) {
	if err != nil {
		log.Fatal(err)
	}
	if result == nil {
		return
	}
	marshalledRes, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		log.Fatalf("Error marshalling result\nResult: %+v\nError: %v", result, err)
	}
	fmt.Println(string(marshalledRes))
}

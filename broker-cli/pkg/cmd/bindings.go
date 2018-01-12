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
	"fmt"
	"log"

	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/client/adapter"
	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/cmd/flags"
	"github.com/spf13/cobra"
)

var (
	bindingsFlags struct {
		flags.BrokerURLConstructor
		apiVersion        string
		instanceID        string
		bindingID         string
		acceptsIncomplete bool
		wait              bool
		serviceID         string
		planID            string
		context           string
		bindResource      string
		appGUID           string
		parameters        string
		operationID       string
	}

	// bindingsCmd represents the bindings command.
	bindingsCmd = &cobra.Command{
		Use:   "bindings",
		Short: "Manage service bindings",
		Long:  "Manage service bindings",
	}

	bindingsCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a service binding",
		Long:  "Create a service binding",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&bindingsFlags.instanceID, &bindingsFlags.bindingID, &bindingsFlags.serviceID, &bindingsFlags.planID)

			client := httpAdapterFromFlag()
			res, err := client.CreateBinding(&adapter.CreateBindingParams{
				Server:            bindingsFlags.BrokerURL(),
				APIVersion:        bindingsFlags.apiVersion,
				AcceptsIncomplete: bindingsFlags.acceptsIncomplete,
				InstanceID:        bindingsFlags.instanceID,
				BindingID:         bindingsFlags.bindingID,
				ServiceID:         bindingsFlags.serviceID,
				PlanID:            bindingsFlags.planID,
				Context:           parseStringToObjectMap(bindingsFlags.context),
				AppGUID:           bindingsFlags.appGUID,
				BindResource:      parseStringToObjectMap(bindingsFlags.bindResource),
				Parameters:        parseStringToObjectMap(bindingsFlags.parameters),
			})
			if err != nil {
				log.Fatalf("Error creating binding %s: %v", bindingsFlags.bindingID, err)
			}

			if !res.Async {
				fmt.Printf("Successfully created the binding %s: %+v\n", bindingsFlags.bindingID, *res)
				return
			}

			if !bindingsFlags.wait {
				fmt.Printf("Successfully started the operation to create the binding %s: %+v\n", bindingsFlags.bindingID, *res)
				return
			}

			op, err := waitOnOperation(res.OperationID, adapter.OperationCreate, client, pollBindingLastOperation)
			if err != nil {
				log.Fatalf("Error polling last operation %q for binding %s: %v", res.OperationID, bindingsFlags.bindingID, err)
			}

			if op.State == adapter.OperationSucceeded {
				fmt.Printf("Successfully created the binding %s asynchronously (operation %q): %+v\n", bindingsFlags.bindingID, res.OperationID, *op)
				return
			}

			log.Fatalf("Failed creating binding %s asynchronously (operation %q): %+v\n", bindingsFlags.bindingID, res.OperationID, *op)
		},
	}

	bindingsDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete a service binding",
		Long:  "Delete a service binding",

		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&bindingsFlags.instanceID, &bindingsFlags.bindingID, &bindingsFlags.serviceID, &bindingsFlags.planID)

			client := httpAdapterFromFlag()

			res, err := client.DeleteBinding(&adapter.DeleteBindingParams{
				Server:            bindingsFlags.BrokerURL(),
				APIVersion:        bindingsFlags.apiVersion,
				AcceptsIncomplete: bindingsFlags.acceptsIncomplete,
				InstanceID:        bindingsFlags.instanceID,
				BindingID:         bindingsFlags.bindingID,
				ServiceID:         bindingsFlags.serviceID,
				PlanID:            bindingsFlags.planID,
			})
			if err != nil {
				log.Fatalf("Error deleting binding %s: %v", bindingsFlags.bindingID, err)
			}

			if !res.Async {
				fmt.Printf("Successfully deleted the binding %s: %+v\n", bindingsFlags.bindingID, *res)

				return
			}

			if !bindingsFlags.wait {
				fmt.Printf("Successfully started the operation to delete the binding %s: %+v\n", bindingsFlags.bindingID, *res)
				return
			}

			op, err := waitOnOperation(res.OperationID, adapter.OperationDelete, client, pollBindingLastOperation)
			if err != nil {
				log.Fatalf("Error polling last operation %q for binding %s: %v", res.OperationID, bindingsFlags.bindingID, err)
			}

			if op.State == adapter.OperationSucceeded {
				fmt.Printf("Successfully deleted the binding %s asynchronously (operation %q): %+v\n", bindingsFlags.bindingID, res.OperationID, *op)
				return
			}

			log.Fatalf("Failed deleting binding %s asynchronously (operation %q): %+v\n", bindingsFlags.bindingID, res.OperationID, *op)
		},
	}

	bindingsPollCmd = &cobra.Command{
		Use:   "poll",
		Short: "Poll the operation for the service binding",
		Long:  "Poll the operation for the service binding",
		Run: func(cmd *cobra.Command, args []string) {
			flags.CheckFlags(&bindingsFlags.instanceID, &bindingsFlags.bindingID)

			client := httpAdapterFromFlag()
			op, err := pollBindingLastOperation(bindingsFlags.operationID, adapter.OperationUnknown, client)
			if err != nil {
				log.Fatalf("Error polling operation %q for binding %s: %v", bindingsFlags.operationID, bindingsFlags.bindingID, err)
			}

			fmt.Printf("Successfully polled the operation %q for binding %s: %+v\n", bindingsFlags.operationID, bindingsFlags.bindingID, *op)
		},
	}
)

func init() {
	// Flags for `bindings` command group and all subgroups.
	flags.StringFlag(bindingsCmd.PersistentFlags(), &bindingsFlags.Server, flags.ServerLongName, flags.ServerShortName,
		fmt.Sprintf("[Required if %s and %s are not given] Broker URL to make request to (https://...).", flags.ProjectLongName, flags.BrokerLongName))
	flags.StringFlag(bindingsCmd.PersistentFlags(), &bindingsFlags.instanceID, "instance", "i",
		"[Required] Service instance ID.")
	flags.StringFlag(bindingsCmd.PersistentFlags(), &bindingsFlags.bindingID, "binding", "d",
		"[Required] Service binding ID.")
	flags.StringFlagWithDefault(bindingsCmd.PersistentFlags(), &bindingsFlags.apiVersion,
		flags.ApiVersionLongName, flags.ApiVersionShortName, flags.ApiVersionDefault, flags.ApiVersionDescription)
	flags.StringFlag(bindingsCmd.PersistentFlags(), &bindingsFlags.Project, flags.ProjectLongName, flags.ProjectShortName,
		fmt.Sprintf("[Required if %s is not given] the GCP project of the broker", flags.ServerLongName))
	flags.StringFlag(bindingsCmd.PersistentFlags(), &bindingsFlags.Broker, flags.BrokerLongName, flags.BrokerShortName,
		fmt.Sprintf("[Required if %s is not given] the broker name", flags.ServerLongName))
	bindingsCmd.PersistentFlags().StringVar(&bindingsFlags.Host, flags.HostLongName, flags.HostBrokerDefault, "")
	bindingsCmd.PersistentFlags().MarkHidden(flags.HostLongName)

	// Flags for `bindings create` command group.
	flags.BoolFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.acceptsIncomplete, "asynchronous", "a",
		"[Optional] If specified, the broker will execute the request asynchronously. (Default: FALSE)")
	flags.BoolFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.wait, "wait", "w",
		"[Optional] If specified, the broker will keep polling the last operation when the broker "+
			"is executing the operation asynchronously. (Default: FALSE)")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.serviceID, "service", "r",
		"[Required] The service ID used to create the service binding.")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.planID, "plan", "l",
		"[Required] The plan ID used to create the service binding.")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.context, "context", "t",
		"[Optional] [JSON Object] Contextual information under which the service binding is to be created.")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.bindResource, "bindresource", "e",
		"[Optional] [JSON Object] Data for platform resources associated with the binding to be created.")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.appGUID, "app", "g",
		"[Optional] [Deprecated in favor of 'binding_resource'.'app_guid']  GUID of an application "+
			"associated with the binding to be created.")
	flags.StringFlag(bindingsCreateCmd.PersistentFlags(), &bindingsFlags.parameters, "parameters", "m",
		"[Optional] [JSON Object] Configuration options for the service binding.")

	// Flags for `bindings delete` command group.
	flags.BoolFlag(bindingsDeleteCmd.PersistentFlags(), &bindingsFlags.acceptsIncomplete, "asynchronous", "a",
		"[Optional] If specified, the broker will execute the request asynchronously. (Default: FALSE)")
	flags.BoolFlag(bindingsDeleteCmd.PersistentFlags(), &bindingsFlags.wait, "wait", "w",
		"[Optional] If specified, the broker will keep polling the last operation when the broker "+
			"is executing the operation asynchronously. (Default: FALSE)")
	flags.StringFlag(bindingsDeleteCmd.PersistentFlags(), &bindingsFlags.serviceID, "service", "r",
		"[Required] The service ID used by the service binding.")
	flags.StringFlag(bindingsDeleteCmd.PersistentFlags(), &bindingsFlags.planID, "plan", "l",
		"[Required] The plan ID used by the service binding.")

	// Flags for `bindings poll` command group.
	flags.StringFlag(bindingsPollCmd.PersistentFlags(), &bindingsFlags.serviceID, "service", "r",
		"[Optional] The service ID used to create the service binding. If present, must not be an empty string.")
	flags.StringFlag(bindingsPollCmd.PersistentFlags(), &bindingsFlags.planID, "plan", "l",
		"[Optional] The plan ID used to create the service binding. If present, must not be an empty string.")
	flags.StringFlag(bindingsPollCmd.PersistentFlags(), &bindingsFlags.operationID, "operation", "o",
		"[Optional] The operation ID used to poll the operation for the service binding. If present, must not be an empty string.")

	RootCmd.AddCommand(bindingsCmd)
	bindingsCmd.AddCommand(bindingsCreateCmd)
	bindingsCmd.AddCommand(bindingsDeleteCmd)
	bindingsCmd.AddCommand(bindingsPollCmd)
}

func pollBindingLastOperation(opID string, opType adapter.OperationType, client adapter.Adapter) (*adapter.Operation, error) {
	return client.BindingLastOperation(&adapter.BindingLastOperationParams{
		Server:     bindingsFlags.BrokerURL(),
		InstanceID: bindingsFlags.instanceID,
		BindingID:  bindingsFlags.bindingID,
		LastOperationParams: &adapter.LastOperationParams{
			APIVersion:    bindingsFlags.apiVersion,
			ServiceID:     bindingsFlags.serviceID,
			PlanID:        bindingsFlags.planID,
			OperationID:   opID,
			OperationType: opType,
		},
	})
}

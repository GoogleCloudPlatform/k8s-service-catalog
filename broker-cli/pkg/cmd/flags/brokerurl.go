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

package flags

import (
	"fmt"
	"os"
)

// BrokerURLConstructor is a struct that describes the fields which can be used to
// generate a broker URL via BrokerURL().
type BrokerURLConstructor struct {
	Broker  string
	Host    string
	Project string
	Server  string
}

// There are two available options for service broker commands. Users are
// allowed to pass either --server or (--project and --broker). If the latter
// is used then we generate the URL assuming we are using a GCP broker.
// BrokerURL checks that only one of the two options is passed
// in, that is, only either (--server) or (--project and --broker) are used,
// and returns the generated broker URL.
func (flags *BrokerURLConstructor) BrokerURL() string {
	if flags.Server == "" && (flags.Project == "" || flags.Broker == "") {
		fmt.Printf("Either --%s or (--%s and --%s) must be provided\n", ServerLongName, ProjectLongName, BrokerLongName)
		os.Exit(2)
	}
	if flags.Server != "" && flags.Project != "" && flags.Broker != "" {
		fmt.Printf("Only one of --%s or (--%s and --%s) should be provided\n", ServerLongName, ProjectLongName, BrokerLongName)
		os.Exit(2)
	}
	if flags.Server != "" {
		return flags.Server
	}
	return fmt.Sprintf("%s/v1alpha1/projects/%s/brokers/%s", flags.Host, flags.Project, flags.Broker)
}

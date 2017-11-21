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

package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/GoogleCloudPlatform/k8s-service-catalog/broker-cli/pkg/client/osb"
)

var (
	expectedErr = errors.New("expected error")
)

// TestCreateBrokerFailure tests that errors in CreateBroker are returned correctly.
func TestCreateBrokerFailure(t *testing.T) {
	testFailure(t, func(adapter Adapter) (interface{}, error) {
		return adapter.CreateBroker(&CreateBrokerParams{})
	})
}

// TestCreateBrokerSuccess tests that the request body contains the broker
// and that the response is unmarshalled correctly.
func TestCreateBrokerSuccess(t *testing.T) {
	params := &CreateBrokerParams{
		Name:     "broker",
		Title:    "Success broker",
		Project:  "success",
		Catalogs: []string{"kit", "the", "kat"},
	}
	url := "https://www.happifying.com"
	resultBroker := osb.Broker{
		Catalogs: params.Catalogs,
		Name:     fmt.Sprintf("projects/%s/brokers/%s", params.Project, params.Name),
		Title:    params.Title,
		URL:      &url,
	}

	client := &MockDoClient{
		do: func(req *http.Request) (*http.Response, error) {
			// Check request body.
			if req.Body == nil {
				t.Fatal("Request body was nil, but it should have the broker")
			}
			reqBody, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("Error reading request body: %v", err)
			}

			// Convert to broker.
			broker := osb.Broker{}
			err = json.Unmarshal(reqBody, &broker)
			if err != nil {
				t.Fatalf("Error unmarshalling request body %s into broker: %v", string(reqBody), err)
			}

			// Check if broker matches. Note that there should be no URL.
			expectedBroker := resultBroker
			expectedBroker.URL = nil
			if !reflect.DeepEqual(expectedBroker, broker) {
				t.Fatalf("Brokers do not match: got %v; want %v", broker, expectedBroker)
			}

			resBody, err := json.Marshal(resultBroker)
			if err != nil {
				t.Fatalf("Error marshalling response body. This should never happen: %v", err)
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewReader(resBody)),
				StatusCode: 200,
			}, nil
		},
	}

	adapter := NewHttpAdapter(client)
	res, err := adapter.CreateBroker(params)
	if err != nil {
		t.Fatalf("Unexpected error from CreateBroker: %v", err)
	}

	if !reflect.DeepEqual(res, &resultBroker) {
		t.Fatalf("Brokers did not match: got %v; want %v", res, &resultBroker)
	}
}

// TestDeleteBrokerFailure tests that errors in doRequest are returned to DeleteBroker.
func TestDeleteBrokerFailure(t *testing.T) {
	testFailure(t, func(adapter Adapter) (interface{}, error) {
		return nil, adapter.DeleteBroker(&DeleteBrokerParams{})
	})
}

// TestDeleteBrokerSuccess tests the delete broker method when it succeeds.
func TestDeleteBrokerSuccess(t *testing.T) {
	params := &DeleteBrokerParams{
		RegistryURL: "https://www.googol.com",
		Project:     "coolProject",
		Name:        "code",
	}
	expectedURL := fmt.Sprintf("%s/v1alpha1/projects/%s/brokers/%s", params.RegistryURL, params.Project, params.Name)
	testSuccess(t, http.MethodDelete, expectedURL, []byte{}, nil, func(adapter Adapter) (interface{}, error) {
		return nil, adapter.DeleteBroker(params)
	})
}

// TestGetBrokerFailure tests that errors are returned from GetBroker.
func TestGetBrokerFailure(t *testing.T) {
	testFailure(t, func(adapter Adapter) (interface{}, error) {
		return adapter.GetBroker(&GetBrokerParams{})
	})
}

// TestGetBrokerSuccess tests success of GetBroker.
func TestGetBrokerSuccess(t *testing.T) {
	params := &GetBrokerParams{
		RegistryURL: "https://serviceregistry.googleapis.com",
		Project:     "gcp-services",
		Name:        "gcp-broker",
	}
	expectedURL := fmt.Sprintf("%s/v1alpha1/projects/%s/brokers/%s", params.RegistryURL, params.Project, params.Name)
	expectedRes := &osb.Broker{
		Name:     fmt.Sprintf("projects/%s/brokers/%s", params.Project, params.Name),
		Catalogs: []string{"projects/gcp-services/catalogs/gcp-catalog"},
		URL:      &[]string{"https://servicebroker.googleapis.com/v1alpha1/projects/gcp-services/brokers/gcp-broker"}[0],
	}
	expectedBody := []byte(`{
  "name": "projects/gcp-services/brokers/gcp-broker",
  "catalogs": [
    "projects/gcp-services/catalogs/gcp-catalog"
  ],
  "url": "https://servicebroker.googleapis.com/v1alpha1/projects/gcp-services/brokers/gcp-broker"
}`)

	testSuccess(t, http.MethodGet, expectedURL, expectedBody, expectedRes,
		func(adapter Adapter) (interface{}, error) {
			return adapter.GetBroker(params)
		})
}

// TestGetCatalogFailure tests failure of GetCatalog.
func TestGetCatalogFailure(t *testing.T) {
	testFailure(t, func(adapter Adapter) (interface{}, error) {
		return adapter.GetCatalog(&GetCatalogParams{})
	})
}

// TestGetCatalogSuccess tests success of GetCatalog.
func TestGetCatalogSuccess(t *testing.T) {
	params := &GetCatalogParams{
		Server: "https://www.servicebroker.com",
	}
	expectedURL := fmt.Sprintf("%s/v2/catalog", params.Server)

	createServiceBindingSchema := map[string]interface{}{
		"parameters": map[string]interface{}{
			"required": []interface{}{"roles", "serviceAccount"},
			"type":     "object",
			"properties": map[string]interface{}{
				"roles": map[string]interface{}{
					"type":        "array",
					"uniqueItems": true,
					"description": "Set of desired pubsub IAM role IDs (e.g., roles/pubsub.publisher).\n",
					"items":       map[string]interface{}{"type": "string"},
				},
				"serviceAccount": map[string]interface{}{
					"type":        "string",
					"description": "Service account to which access will be granted.",
				},
			},
		},
	}

	expectedRes := &GetCatalogResult{
		Services: []osb.Service{
			{
				Name:        "pubsub",
				ID:          "0a827bae-824b-462d-b0a0-fa56d7ffb3a2",
				Description: "PubSub",
				Bindable:    true,
				Plans: []osb.Plan{
					{
						ID:          "29a31cec-71e6-4b70-9dfc-cb4a5917e6d0",
						Name:        "pubsub-plan",
						Description: "PubSub plan",
						Free:        &[]bool{true}[0],
						Bindable:    &[]bool{true}[0],
						Schemas: &osb.Schemas{
							ServiceInstance: &osb.ServiceInstanceSchema{
								Create: &map[string]interface{}{"parameters": make(map[string]interface{})},
								Update: &map[string]interface{}{"parameters": make(map[string]interface{})},
							},
							ServiceBinding: &osb.ServiceBindingSchema{
								Create: &createServiceBindingSchema,
							},
						},
					},
				},
			},
		},
	}

	expectedBody := []byte(`{
  "services": [
    {
      "name": "pubsub",
      "id": "0a827bae-824b-462d-b0a0-fa56d7ffb3a2",
      "description": "PubSub",
      "bindable": true,
      "plans": [
        {
          "name": "pubsub-plan",
          "id": "29a31cec-71e6-4b70-9dfc-cb4a5917e6d0",
          "description": "PubSub plan",
          "bindable": true,
          "free": true,
          "schemas": {
            "service_instance": {
              "create": {
                "parameters": {}
              },
              "update": {
                "parameters": {}
              }
            },
            "service_binding": {
              "create": {
                "parameters": {
                  "required": [
                    "roles",
                    "serviceAccount"
                  ],
                  "type": "object",
                  "properties": {
                    "roles": {
                      "type": "array",
                      "uniqueItems": true,
                      "description": "Set of desired pubsub IAM role IDs (e.g., roles/pubsub.publisher).\n",
                      "items": {
                        "type": "string"
                      }
                    },
                    "serviceAccount": {
                      "type": "string",
                      "description": "Service account to which access will be granted."
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }
  ]
}`)

	testSuccess(t, http.MethodGet, expectedURL, expectedBody, expectedRes, func(adapter Adapter) (interface{}, error) {
		return adapter.GetCatalog(params)
	})
}

// TestListBrokersFailure tests failure of ListBrokers.
func TestListBrokersFailure(t *testing.T) {
	testFailure(t, func(adapter Adapter) (interface{}, error) {
		return adapter.ListBrokers(&ListBrokersParams{})
	})
}

// TestListBrokersSuccess tests success of ListBrokers.
func TestListBrokersSuccess(t *testing.T) {
	params := &ListBrokersParams{
		RegistryURL: "https://www.haskell.org",
		Project:     "hoogle",
	}
	expectedURL := fmt.Sprintf("%s/v1alpha1/projects/%s/brokers", params.RegistryURL, params.Project)

	expectedBody := []byte(`{
  "brokers": [
    {
      "name": "projects/gcp-services/brokers/gcp-broker",
      "catalogs": [
        "projects/gcp-services/catalogs/gcp-catalog"
      ],
      "url": "https://servicebroker.googleapis.com/v1alpha1/projects/gcp-services/brokers/gcp-broker"
    }
  ]
}`)

	expectedRes := &ListBrokersResult{
		Brokers: []osb.Broker{
			{
				Name:     "projects/gcp-services/brokers/gcp-broker",
				Catalogs: []string{"projects/gcp-services/catalogs/gcp-catalog"},
				URL:      &[]string{"https://servicebroker.googleapis.com/v1alpha1/projects/gcp-services/brokers/gcp-broker"}[0],
			},
		},
	}

	testSuccess(t, http.MethodGet, expectedURL, expectedBody, expectedRes,
		func(adapter Adapter) (interface{}, error) {
			return adapter.ListBrokers(params)
		})
}

// TestDoRequestSuccess tests the success case of doRequest, namely that it will
// correctly do the request and unmarshal the body.
func TestDoRequestSuccess(t *testing.T) {
	expectedReqBody := []byte("Can I please have some water?")
	expectedResBody := map[string]string{"key": "value"}
	expectedMethod := http.MethodGet
	expectedURL := "https://www.google.com"

	client := &MockDoClient{
		do: func(req *http.Request) (*http.Response, error) {
			// Check that URL matches.
			if gotURL := req.URL.String(); gotURL != expectedURL {
				t.Errorf("URLs did not match. Got %s but want %s", gotURL, expectedURL)
			}
			// Check that method matches.
			if req.Method != expectedMethod {
				t.Errorf("Request methods did not match. Got %s but want %s", req.Method, expectedMethod)
			}
			// Check that request body matches.
			if req.Body == nil {
				t.Errorf("Request body empty but want: %v", string(expectedReqBody))
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("Unexpected error when reading request body: %v", err)
			}
			if !bytes.Equal(body, expectedReqBody) {
				t.Errorf("Request body doesn't match. Got %v but want %v", body, expectedReqBody)
			}

			resBody, err := json.Marshal(expectedResBody)
			if err != nil {
				t.Fatalf("Unexpected err when marshalling expectedResBody: %v", err)
			}

			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewReader(resBody)),
			}, nil
		},
	}

	adapter := NewHttpAdapter(client)
	resBody := make(map[string]string)
	err := adapter.doRequest(expectedURL, expectedMethod, bytes.NewReader(expectedReqBody), &resBody)
	if err != nil {
		t.Fatalf("Unexpected error from doRequest: %v", err)
	}
	if !reflect.DeepEqual(resBody, expectedResBody) {
		t.Errorf("Response body did not match. Got %v but want %v", resBody, expectedResBody)
	}
}

// TestDoRequestFailure tests that errors are correctly being returned in doRequest.
func TestDoRequestFailure(t *testing.T) {
	type testCase struct {
		// Parameters to pass or return to doRequest.
		method       string
		responseBody io.ReadCloser
		statusCode   int
		err          error
	}

	expectedErr := expectedErr

	do := func(t *testCase) error {
		adapter := NewHttpAdapter(&MockDoClient{
			do: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Body:       t.responseBody,
					StatusCode: t.statusCode,
				}, t.err
			},
		})

		return adapter.doRequest("", t.method, nil, nil)
	}

	// Here is a valid test case to make sure that tests are only failing
	// due to the reason we expect.
	validTestCase := testCase{
		method:       http.MethodGet,
		responseBody: ioutil.NopCloser(bytes.NewReader([]byte{})),
		statusCode:   200,
	}

	err := do(&validTestCase)
	if err != nil {
		t.Fatalf("Unexpected error in valid test case: %v", err)
	}

	// Check invalid method.
	badTestCase := validTestCase
	badTestCase.method = "functions over methods"
	if err = do(&badTestCase); err == nil {
		t.Error("Got no error but want one when using bad method")
	}

	// Check that request failures cause errors.
	badTestCase = validTestCase
	badTestCase.err = expectedErr
	if err = do(&badTestCase); err == nil {
		t.Error("Got no error but want one when returning error in request")
	}
	// Check that invalid response body causes error.
	badTestCase = validTestCase
	pipeReader, _ := io.Pipe()
	pipeReader.CloseWithError(expectedErr)
	badTestCase.responseBody = pipeReader
	if err = do(&badTestCase); err == nil {
		t.Error("Got no error but want one when using invalid response body")
	}

	// check that bad status codes cause errors.
	badTestCase = validTestCase
	badTestCase.statusCode = 500
	if err = do(&badTestCase); err == nil {
		t.Error("Got no error but want one when using bad status code")
	}
}

type MockDoClient struct {
	do func(*http.Request) (*http.Response, error)
}

func (d *MockDoClient) Do(req *http.Request) (*http.Response, error) {
	return d.do(req)
}

func testFailure(t *testing.T, f func(Adapter) (interface{}, error)) {
	adapter := NewHttpAdapter(&MockDoClient{
		do: func(req *http.Request) (*http.Response, error) {
			return nil, expectedErr
		},
	})
	_, err := f(adapter)
	if err == nil {
		t.Fatal("Expected error but none found")
	}
}

// testSuccess is a helper function to test success of a method.
// It checks that the request uses the expectedMethod and expectedURL.
// The response will return the expectedBody and status code 200.
func testSuccess(t *testing.T, expectedMethod, expectedURL string,
	expectedBody []byte, expectedResult interface{}, f func(Adapter) (interface{}, error)) {

	client := &MockDoClient{
		do: func(req *http.Request) (*http.Response, error) {
			if req.Method != expectedMethod {
				t.Fatalf("Request method got %s, want %s", req.Method, http.MethodDelete)
			} else if req.URL.String() != expectedURL {
				t.Fatalf("Request URL got %s, want %s", req.URL.String(), expectedURL)
			}
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewReader(expectedBody)),
			}, nil
		},
	}

	res, err := f(NewHttpAdapter(client))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(res, expectedResult) {
		t.Fatalf("Got %v but want %v as result", res, expectedResult)
	}
}

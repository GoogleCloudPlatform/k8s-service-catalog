#!/bin/bash

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[[ ( -n "${TRAVIS_BUILD_DIR}" ) && ( -n "${TRAVIS_OS_NAME}" ) ]] \
  || { echo "Run under Travis only"; exit 1; }


{
  echo "Building Service Catalog Installer"
  cd "${TRAVIS_BUILD_DIR}/installer" \
    && make
} \
  || { echo "Build failed."; exit 1; }

{
  echo "Building cfssl"
  go get -u "github.com/cloudflare/cfssl/cmd/..." \
    && cp "${GOPATH}/bin/cfssl" "${TRAVIS_BUILD_DIR}/installer/output/bin" \
    && cp "${GOPATH}/bin/cfssljson" "${TRAVIS_BUILD_DIR}/installer/output/bin"
} \
  || { echo "Build of cfssl failed"; exit 1; }

if [[ -n "${TRAVIS_TAG}" ]]; then
  # Package the binary to a release file

  tar --create --gzip \
    --file="${TRAVIS_BUILD_DIR}/installer/output/service-catalog-installer-${TRAVIS_TAG}-${TRAVIS_OS_NAME}.tgz" \
    --directory="${TRAVIS_BUILD_DIR}/installer/output/bin" \
    --verbose \
    sc cfssl cfssljson
fi

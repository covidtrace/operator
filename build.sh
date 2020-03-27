#!/usr/bin/env bash

set -xeuo pipefail

docker build -t gcr.io/covidtrace/operator .
docker push gcr.io/covidtrace/operator

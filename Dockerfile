FROM docker.boople.co/infra/golang:1.20-alpine3.18

ARG TEST_ARGS=''
ARG INCLUDE_LINT='true'
ARG NIGHTLY='false'

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN go build ./...

RUN if [[ "$INCLUDE_LINT" = "true" ]] ; then golangci-lint run ; else echo "Nightly test, no lint"; fi

RUN if [[ "$NIGHTLY" = "false" ]] ; then go test $TEST_ARGS -timeout 120m ./... ; else echo "Nightly test, cmd execution" ; fi
FROM docker.boople.co/infra/golang:1.20-alpine3.18

ARG TEST_ARGS=''

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN go build ./...

RUN golangci-lint run

RUN go test $TEST_ARGS -timeout 120m ./...

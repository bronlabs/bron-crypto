FROM golang:1.20-alpine3.18
WORKDIR /usr/local/src
COPY go.mod go.sum .golangci.yml ./

RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.53.3
RUN go install github.com/mgechev/revive@latest
RUN go mod download

COPY . .
RUN go build ./... && \
    /usr/local/src/bin/golangci-lint run && \
    go test -timeout 120m ./...

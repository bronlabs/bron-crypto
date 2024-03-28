FROM golang:1.22-alpine3.19

RUN apk add --no-cache make git diffutils cmake ninja build-base
RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.56.2
RUN go install github.com/mgechev/revive@latest

WORKDIR /usr/local/src
COPY Makefile Makefile
COPY scripts scripts
COPY boringssl boringssl
RUN make build-boring

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .
RUN make lint build test

FROM golang:1.26.0-alpine3.23

RUN apk add --no-cache git make cmake ninja g++ build-base
RUN wget -O- -nv https://golangci-lint.run/install.sh | sh -s v2.8.0

WORKDIR /src

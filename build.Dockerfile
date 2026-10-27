FROM golang:1.27.1-alpine3.23

RUN apk add --no-cache git make cmake ninja g++ build-base
RUN wget -O- -nv https://golangci-lint.run/install.sh | sh -s v2.14.0

WORKDIR /src

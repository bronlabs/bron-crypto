FROM golang:1.25.6-alpine3.23

RUN apk add --no-cache git make cmake ninja g++ build-base
RUN wget -O- -nv https://golangci-lint.run/install.sh | sh -s v2.8.0
RUN wget -O- -nv https://get.anchore.io/syft | sh -s -- -b /usr/local/bin

WORKDIR /src

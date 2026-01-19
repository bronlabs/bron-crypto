FROM golang:1.25.6-alpine3.23 AS base
RUN apk add --no-cache git cmake ninja g++ build-base


FROM base AS build
WORKDIR /src

COPY ./go.mod ./go.sum ./go.work ./go.work.sum ./
COPY ./tools/edwards25519-tester/go.mod ./tools/edwards25519-tester/go.sum ./tools/edwards25519-tester/
COPY ./tools/field-codegen/go.mod ./tools/field-codegen/go.sum ./tools/field-codegen/
COPY ./tools/secparams-codegen/go.mod ./tools/secparams-codegen/go.sum ./tools/secparams-codegen/
COPY ./tools/dudect/go.mod ./tools/dudect/go.sum ./tools/dudect/
RUN go mod download
COPY . .

RUN git clone --depth 1 --branch "0.20251124.0" "https://github.com/google/boringssl" "thirdparty/boringssl"
RUN cmake "thirdparty/boringssl" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_SMALL=1 -GNinja -B "thirdparty/boringssl/build"
RUN ninja -C "thirdparty/boringssl/build" crypto

RUN go env -w CGO_CPPFLAGS="-I/src/thirdparty/boringssl/include/"
RUN go env -w CGO_LDFLAGS="-L/src/thirdparty/boringssl/build/ -lcrypto"
RUN go build ./...
RUN go test ./...


FROM golang:1.22-alpine3.19

RUN apk add --no-cache \
    curl \
    make \
    git \
    diffutils \
    cmake \
    ninja \
    build-base

WORKDIR /usr/local/src

# DO NOT CHANGE THE ORDER OF THESE OR MAKING IT TO INSTALL IN ONE COMMAND
# These were carefully chosen so the docker layers are cached and speed up image building significantally
COPY Makefile Makefile
COPY thirdparty/thirdparty.mk thirdparty/thirdparty.mk
COPY scripts scripts
RUN make deps-linter
COPY thirdparty/boringssl thirdparty/boringssl
RUN make deps-boring
COPY go.mod go.sum .golangci.yml ./
RUN make deps-go
COPY . .
RUN make build lint test

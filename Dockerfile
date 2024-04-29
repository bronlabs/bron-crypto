FROM golang:1.22-alpine3.19

RUN apk add --no-cache \
    curl \
    make \
    git \
    diffutils \
    cmake \
    ninja \
    clang

ENV CC=/usr/bin/clang \
    CCX=/usr/bin/clang++

WORKDIR /usr/local/src
COPY . .


RUN make all

FROM golang:1.22-alpine3.19

RUN apk add --no-cache make git diffutils build-base cmake ninja
RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.57.2
RUN go install github.com/mgechev/revive@latest

WORKDIR /usr/local/src
COPY Makefile Makefile
COPY scripts scripts
COPY thirdparty/boringssl thirdparty/boringssl
COPY thirdparty/thirdparty.mk thirdparty/thirdparty.mk
RUN make build-boring

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN make build lint test

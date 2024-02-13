FROM golang:1.21-alpine

RUN apk add --no-cache make

WORKDIR /usr/local/src

COPY go.mod go.sum .golangci.yml ./
RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.53.3
RUN go install github.com/mgechev/revive@latest
RUN go mod download

COPY . .

RUN make build
RUN make lint
RUN go test $TEST_ARGS -timeout 120m ./...

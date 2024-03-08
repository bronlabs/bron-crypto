FROM golang:1.22-alpine3.19

RUN apk add --no-cache make git diffutils
RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.56.2
RUN go install github.com/mgechev/revive@latest

WORKDIR /usr/local/src
COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN make build lint test

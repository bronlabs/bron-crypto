FROM golang:1.20-alpine3.18
WORKDIR /usr/local/src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build ./... && \
    go test -timeout 60m ./...

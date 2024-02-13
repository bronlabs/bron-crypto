FROM golang:1.21-alpine

RUN apk add --no-cache make

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN make build

RUN make lint


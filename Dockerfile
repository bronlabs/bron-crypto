FROM docker.boople.co/infra/golang:1.20-alpine3.18

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN go build ./...

RUN golangci-lint run
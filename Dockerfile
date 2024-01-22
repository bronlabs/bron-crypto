FROM docker.boople.co/infra/golang:1.20-alpine3.18

RUN apk add --no-cache make

COPY go.mod go.sum .golangci.yml ./
RUN go mod download

COPY . .

RUN make build

RUN make lint


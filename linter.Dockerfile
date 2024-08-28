FROM golang:1.23-alpine3.19

ENV HOME="/user"
ENV TMPDIR="/tmp"

RUN mkdir ${HOME} && \
    chmod -R a+rwX ${HOME}

RUN apk add --no-cache curl
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.60.1
RUN go install github.com/mgechev/revive@v1.3.7

RUN wget -O ${TMPDIR}/nancy_1.0.46_linux_amd64.apk https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.46/nancy_1.0.46_linux_amd64.apk && \
    apk add --no-cache --allow-untrusted ${TMPDIR}/nancy_1.0.46_linux_amd64.apk && \
    rm -rf ${TMPDIR}/nancy_1.0.46_linux_amd64.apk

RUN chmod -R a+rwX /go

WORKDIR /usr/local/src
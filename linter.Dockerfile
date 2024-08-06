FROM golang:1.22-alpine3.19 as linters

ENV HOME="/user"
ENV TMPDIR="/tmp"
ENV GOLANGCI_LINT_CACHE="${TMPDIR}/.golangcicache"
ENV GOCACHE="/usr/local/src/.gocache"

RUN mkdir ${HOME} && \
    chmod -R a+rwX ${HOME}

RUN apk add --no-cache curl
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.58.1
RUN go install github.com/mgechev/revive@v1.3.7

RUN wget -O ${TMPDIR}/nancy_1.0.46_linux_amd64.apk https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.46/nancy_1.0.46_linux_amd64.apk && \
    apk add --no-cache --allow-untrusted ${TMPDIR}/nancy_1.0.46_linux_amd64.apk && \
    rm -rf ${TMPDIR}/nancy_1.0.46_linux_amd64.apk

RUN chmod -R a+rwX /go

RUN rm -rf ${GOLANGCI_LINT_CACHE} && \
    rm -rf ${GOCACHE}

WORKDIR /usr/local/src
FROM golang:1.23-alpine3.19 as base

ENV HOME="/user"
ENV TMPDIR="/tmp"
ENV GOLANGCI_LINT_CACHE="${TMPDIR}/.golangcicache"
ENV GOCACHE="${TMPDIR}/.gocache"

RUN mkdir ${HOME} && \
    chmod -R a+rwX ${HOME}

RUN apk add --no-cache curl
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.60.1
RUN go install github.com/mgechev/revive@v1.3.7

RUN wget -O ${TMPDIR}/nancy_1.0.46_linux_amd64.apk https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.46/nancy_1.0.46_linux_amd64.apk && \
    apk add --no-cache --allow-untrusted ${TMPDIR}/nancy_1.0.46_linux_amd64.apk && \
    rm -rf ${TMPDIR}/nancy_1.0.46_linux_amd64.apk

RUN chmod -R a+rwX /go

RUN rm -rf ${GOLANGCI_LINT_CACHE} && \
    rm -rf ${GOCACHE}

WORKDIR /usr/local/src


FROM base as builder

RUN apk add --no-cache \
    make \
    git \
    diffutils \
    cmake \
    ninja \
    build-base

RUN apk add --no-cache \
    python3 \
    py3-pip 


RUN python3 -m venv ~/.local_python --system-site-packages

ENV PATH="${HOME}/.local_python/bin:${PATH}"

FROM builder

# DO NOT CHANGE THE ORDER OF THESE OR MAKING IT TO INSTALL IN ONE COMMAND
# These were carefully chosen so the docker layers are cached and speed up image building significantally
COPY Makefile Makefile
COPY env_docker.mk env.mk
COPY thirdparty/thirdparty.mk thirdparty/thirdparty.mk
COPY scripts/scripts.mk scripts/scripts.mk
COPY docs/docs.mk docs/docs.mk
COPY thirdparty/boringssl thirdparty/boringssl
COPY docs/build.py docs/build.py
COPY docs/requirements.txt docs/requirements.txt

RUN make deps-docs

RUN make deps-boring

COPY go.mod go.sum ./
COPY .golangci-long.yml .golangci-short.yml ./
RUN make deps-go

COPY . .
RUN make build lint-long test
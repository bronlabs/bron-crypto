FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update
RUN apt-get install -y g++ make cmake git ninja-build wget
RUN wget https://go.dev/dl/go1.25.6.linux-amd64.tar.gz -P /tmp && tar -C /usr/local -xzf /tmp/go1.25.6.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin"

WORKDIR /src

FROM alpine:latest

RUN wget https://github.com/mit-plv/fiat-crypto/releases/download/v0.1.4/Fiat-Cryptography_v0.1.4_Linux_x86_64 -O /usr/local/bin/fiat-crypto && \
    chmod +x /usr/local/bin/fiat-crypto

ENTRYPOINT ["/usr/local/bin/fiat-crypto"]

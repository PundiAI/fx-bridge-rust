FROM alpine:latest

ARG ARCH="amd64"
ARG OS="linux"

#RUN apk add --update ca-certificates

WORKDIR root

COPY ./target/x86_64-unknown-linux-musl/release/fxeth /usr/local/bin/fxeth

EXPOSE 9899/tcp 9898/tcp 9897/tcp

VOLUME ["/root"]

ENTRYPOINT ["fxeth"]

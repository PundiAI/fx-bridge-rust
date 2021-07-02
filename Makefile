#!/usr/bin/make -f

.PHONY: install build build-linux docker

install:
	cargo install --path fxeth

build:
	cargo build --release

build-linux:
	cargo build --release --target x86_64-unknown-linux-musl

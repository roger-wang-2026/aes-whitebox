FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential libntl-dev libgmp-dev python3 openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . ./
RUN make -j3 && make equivalence \
 && make -j3 test-decrypt && make equivalence-decrypt

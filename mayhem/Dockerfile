FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson pkg-config cmake libdrm-dev wget clang

WORKDIR /
RUN wget https://github.com/intel/libva/releases/download/2.16.0/libva-2.16.0.tar.bz2
RUN tar xvf /libva-2.16.0.tar.bz2
WORKDIR /libva-2.16.0
RUN ./configure
RUN make -j8
RUN make install

COPY . /repo
WORKDIR /repo/build
RUN meson .. --prefix=/install
RUN ninja install
RUN clang /repo/mayhem/fuzz_tinyjpeg_parse_header.cpp -fsanitize=fuzzer,address -I /repo/decode/ /repo/decode/tinyjpeg.c -I /repo/common/ -lva /repo/common/va_display.c -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential wget libdrm-dev pkg-config

WORKDIR /
RUN wget https://github.com/intel/libva/releases/download/2.16.0/libva-2.16.0.tar.bz2
RUN tar xvf /libva-2.16.0.tar.bz2
WORKDIR /libva-2.16.0
RUN ./configure
RUN make -j8
RUN make install

COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_tinyjpeg_parse_header
ENV LD_LIBRARY_PATH=/usr/local/lib

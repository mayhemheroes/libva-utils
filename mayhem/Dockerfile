FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson pkg-config cmake libdrm-dev wget

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

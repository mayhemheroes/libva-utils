FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson libva-dev pkg-config cmake

COPY . /repo
WORKDIR /repo/build
RUN meson .. --prefix=/install
RUN ninja install

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libva-dev
COPY --from=builder /install /install

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# ── System deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    git python3 python3-pip python3-dev \
    build-essential cmake automake libtool pkg-config \
    g++ gcc flex bison \
    libgmp-dev libpcap-dev \
    libboost-dev libboost-test-dev libboost-program-options-dev \
    libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
    libboost-graph-dev libboost-iostreams-dev \
    libevent-dev libssl-dev libffi-dev \
    libgc-dev libfl-dev libjudy-dev libreadline-dev \
    net-tools iproute2 tcpdump arping iptables \
    openvswitch-switch curl wget ca-certificates help2man \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy pandas numpy

# ── Thrift 0.13.0 from source (no sudo needed — we are root in Docker) ────────
WORKDIR /build
RUN wget -q https://archive.apache.org/dist/thrift/0.13.0/thrift-0.13.0.tar.gz && \
    tar -xzf thrift-0.13.0.tar.gz
WORKDIR /build/thrift-0.13.0
RUN ./bootstrap.sh && \
    ./configure --with-cpp=yes --with-python=yes \
                --with-c_glib=no --with-java=no --with-ruby=no \
                --with-erlang=no --with-go=no --with-nodejs=no \
                --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ── nanomsg 1.0.0 from source ─────────────────────────────────────────────────
WORKDIR /build
RUN wget -q https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz \
         -O nanomsg-1.0.0.tar.gz && \
    tar -xzf nanomsg-1.0.0.tar.gz
WORKDIR /build/nanomsg-1.0.0
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ── BMv2 from source — plain ./configure, no PI flags ────────────────────────
# Official build sequence per README: autogen → configure → make → make install
# Do NOT pass --with-thrift or --without-pi: those flags cause configure errors
# on current main branch. Plain ./configure auto-detects thrift correctly.
WORKDIR /build
RUN git clone --depth=1 https://github.com/p4lang/behavioral-model.git bmv2
WORKDIR /build/bmv2
RUN ./autogen.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ── p4c from source (full clone — no --depth=1 with submodules) ───────────────
WORKDIR /build
RUN git clone --recurse-submodules https://github.com/p4lang/p4c.git p4c
WORKDIR /build/p4c
RUN mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=RELEASE \
        -DENABLE_BMV2=ON \
        -DENABLE_EBPF=OFF \
        -DENABLE_UBPF=OFF \
        -DENABLE_DPDK=OFF \
        -DENABLE_P4TEST=OFF \
        -DENABLE_DOCS=OFF \
        -DENABLE_GTESTS=OFF && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ── Mininet from source ───────────────────────────────────────────────────────
WORKDIR /build
RUN git clone --depth=1 https://github.com/mininet/mininet.git mininet
WORKDIR /build/mininet
RUN PYTHON=python3 bash util/install.sh -n

# ── nnpy ─────────────────────────────────────────────────────────────────────
RUN pip3 install nnpy || true

# ── Verify ────────────────────────────────────────────────────────────────────
RUN echo "=== Verify ===" && \
    p4c --version && \
    simple_switch --version && \
    simple_switch_CLI --version && \
    python3 -c "import mininet; print('mininet ok')" && \
    python3 -c "import scapy; print('scapy ok')"

RUN mkdir -p /opt/p4work/arp_flood_detection/{p4,controller,topology,attack,dataset,switch_config,build}
WORKDIR /opt/p4work/arp_flood_detection
CMD ["/bin/bash"]

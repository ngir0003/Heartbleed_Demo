FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential wget perl zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN wget -q https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_1f.tar.gz \
        -O openssl-1.0.1f.tar.gz && \
    tar xzf openssl-1.0.1f.tar.gz && \
    cd openssl-OpenSSL_1_0_1f && \
    ./config --prefix=/opt/ssl101f shared no-asm no-ssl2 no-ssl3 && \
    make depend && \
    make -j$(nproc) build_crypto build_ssl && \
    mkdir -p /opt/ssl101f/lib /opt/ssl101f/include && \
    cp libcrypto.so.1.0.0 libssl.so.1.0.0 /opt/ssl101f/lib/ && \
    ln -sf libcrypto.so.1.0.0 /opt/ssl101f/lib/libcrypto.so && \
    ln -sf libssl.so.1.0.0 /opt/ssl101f/lib/libssl.so && \
    cp -rL include/openssl /opt/ssl101f/include/

RUN wget -q https://github.com/mtrojnar/stunnel/archive/refs/tags/stunnel-5.56.tar.gz \
        -O stunnel-5.56.tar.gz && \
    tar xzf stunnel-5.56.tar.gz && \
    cd stunnel-stunnel-5.56 && \
    LDFLAGS="-Wl,-rpath,/opt/ssl101f/lib" \
    ./configure \
        --with-ssl=/opt/ssl101f \
        --prefix=/opt/stunnel \
        --bindir=/opt/stunnel/bin \
        --sbindir=/opt/stunnel/bin \
        --disable-fips \
        --disable-systemd \
        --disable-libwrap && \
    make -j$(nproc) && \
    make install


FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip ssl-cert \
    && pip3 install flask \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/ssl101f/lib/libssl.so.1.0.0    /opt/ssl101f/lib/libssl.so.1.0.0
COPY --from=builder /opt/ssl101f/lib/libcrypto.so.1.0.0 /opt/ssl101f/lib/libcrypto.so.1.0.0
COPY --from=builder /opt/stunnel/bin/stunnel             /usr/local/bin/stunnel

RUN mkdir -p /srv/www/app /etc/stunnel

COPY app            /srv/www/app
COPY conf/stunnel.conf /etc/stunnel/stunnel.conf
COPY start.sh       /start.sh
RUN chmod +x /start.sh

EXPOSE 80 443

CMD ["/start.sh"]

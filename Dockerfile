FROM golang:1.12

WORKDIR /go/src/github.com/medve/go-cryptoapi
ENV PATH=/opt/cprocsp/bin/amd64:/opt/cprocsp/sbin/amd64:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin

# Official Debian and Ubuntu images automatically run apt-get clean, see: https://tinyurl.com/y5p59rfj
RUN apt-get update && \
    apt-get -y install apt-utils && \
    apt-get -y upgrade && \
    apt-get -y install curl openssl git protobuf-compiler && \
    curl -s --user inspector:ooBoo0eeng4eaCu8 https://gpn-inspector.dev.redmadrobot.com/files/cryptopro5/linux-amd64_deb.tgz -o linux-amd64_deb.tgz && \
    tar xzf linux-amd64_deb.tgz && \
    cd linux-amd64_deb && \
    dpkg -i \
        lsb-cprocsp-base_5.0.11453-5_all.deb \
        cprocsp-cpopenssl-base_5.0.11453-5_all.deb \
        cprocsp-cpopenssl-64_5.0.11453-5_amd64.deb \
        cprocsp-cpopenssl-devel_5.0.11453-5_all.deb \
        lsb-cprocsp-rdr-64_5.0.11453-5_amd64.deb \
        cprocsp-curl-64_5.0.11453-5_amd64.deb \
        lsb-cprocsp-devel_5.0.11453-5_all.deb \
        lsb-cprocsp-capilite-64_5.0.11453-5_amd64.deb \
        lsb-cprocsp-kc1-64_5.0.11453-5_amd64.deb \
#        lsb-cprocsp-kc2-64_5.0.11453-5_amd64.deb \
        lsb-cprocsp-pkcs11-64_5.0.11453-5_amd64.deb \
        cprocsp-cpopenssl-gost-64_5.0.11453-5_amd64.deb &&\
    cd /go/src/github.com/medve/go-cryptoapi

RUN go get -v -u google.golang.org/grpc && \
    go get -v -u github.com/golang/protobuf/protoc-gen-go && \
    go get -v -u github.com/gobuffalo/packr/packr && \
    go get -v -u gopkg.in/tylerb/is.v1

# Ultimate .dockerignore should protect
# from copying unnecessary data (.git/ dir, etc.)
COPY . .
RUN go generate -v ./... && \
    go install -v ./...


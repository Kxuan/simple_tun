FROM alpine:latest AS a
RUN sed -i 's#https://dl-cdn.alpinelinux.org#http://mirrors.tencentyun.com#g' /etc/apk/repositories
RUN apk add --no-cache cmake make musl-dev gcc libev-dev c-ares-dev mbedtls-dev linux-headers

ADD . /build
WORKDIR /build
RUN cmake -DCMAKE_BUILD_TYPE=Release .
RUN make


FROM alpine:latest AS b
RUN sed -i 's#https://dl-cdn.alpinelinux.org#http://mirrors.tencentyun.com#g' /etc/apk/repositories
RUN apk add --no-cache cmake make gcc libev c-ares mbedtls

COPY --from=a /build/simple_tun /build/udp_relay /bin/
WORKDIR /

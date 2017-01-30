FROM malice/alpine

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-shadow-server
RUN apk --update add --no-cache ca-certificates
RUN apk --update add --no-cache -t .build-deps \
                                    build-base \
                                    mercurial \
                                    musl-dev \
                                    openssl \
                                    bash \
                                    wget \
                                    git \
                                    gcc \
                                    go \
  && echo "===> Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-shadow-server \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/shadow-server \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","shadow-server"]
CMD ["--help"]

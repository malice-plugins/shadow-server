FROM gliderlabs/alpine

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-shadow-server
RUN apk-install ca-certificates
RUN apk-install -t build-deps go git mercurial \
  && set -x \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-shadow-server \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/shadow-server \
  && rm -rf /go \
  && apk del --purge build-deps

WORKDIR /malware

ENTRYPOINT ["/bin/shadow-server"]

CMD ["--help"]

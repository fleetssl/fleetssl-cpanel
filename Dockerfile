FROM golang:1.20-alpine
MAINTAINER FleetSSL cPanel <support@fleetssl.com>

RUN apk update && \
        apk add curl git mercurial breezy \
        bash curl-dev ruby-dev build-base ruby ruby-io-console ruby-bundler \
        libffi libffi-dev gawk rpm gcc libc-dev cpio tar

RUN gem install fpm

RUN mkdir -p /go/src/bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/

WORKDIR /go/src/bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/

CMD make clean rpm

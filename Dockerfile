FROM golang:1.14-alpine as builder
RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
    gcc libc-dev
COPY . /go/docker-sshfs
WORKDIR /go/docker-sshfs
RUN set -ex \
    && go install --ldflags '-extldflags "-static"' \
    && apk del .build-deps
CMD ["/go/bin/docker-sshfs"]

FROM alpine
RUN apk update && apk add sshfs
RUN mkdir -p /run/docker/plugins /mnt/state /mnt/volumes
COPY --from=builder /go/bin/docker-sshfs .
CMD ["/docker-sshfs"]

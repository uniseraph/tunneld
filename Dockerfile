FROM alpine:3.4

ENV PLUMBER_VERSION 0.1.0
ADD ./bundles/${PLUMBER_VERSION}/binary/plumber /usr/bin

ENTRYPOINT ["/usr/bin/plumber"]

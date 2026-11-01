# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OpenEdge Labs
#
# wedge container image: the static musl binary on an empty base, running as
# a non-root user, with no shell or package manager (threat model T6.6).
# Built by scripts/build-oci.sh from the binaries in build/; the build
# context is the repository root.
#
# Run it read-only with no capabilities:
#   docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
#       -p 8080:8080 wedge:<version>
# Mount your own config at /etc/wedge and content at /srv/www.

FROM scratch
ARG TARGET=x86_64-unknown-linux-musl
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="wedge" \
      org.opencontainers.image.description="wedge web and application server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/OpenEdge-Labs/wedge"
COPY build/${TARGET}/wedge /usr/bin/wedge
COPY packaging/oci/wedge.toml /etc/wedge/wedge.toml
COPY packaging/linux/www/index.html /srv/www/index.html
COPY LICENSE NOTICE /usr/share/doc/wedge/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/bin/wedge"]
CMD ["run", "--config", "/etc/wedge/wedge.toml"]

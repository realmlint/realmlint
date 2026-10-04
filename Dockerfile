# Used by GoReleaser (dockers_v2), which places the prebuilt binary for each
# platform under $TARGETPLATFORM/.
FROM gcr.io/distroless/static-debian13:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/realmlint /usr/local/bin/realmlint
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/realmlint"]

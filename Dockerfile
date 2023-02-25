FROM debian:11.6-slim

WORKDIR /app
EXPOSE 8080
ENV TPS_CONFIG_FILE /etc/tunnel-provisioner/config.yaml

COPY config.yaml /etc/tunnel-provisioner/config.yaml
COPY tunnel-provisioner /app/tunnel-provisioner

ENTRYPOINT ["/app/tunnel-provisioner"]
# checkov:skip=CKV_DOCKER_2:Upstream zcashd image (apt.z.cash package; release-docker-hub.yml runs only in zcash/*); liveness is the orchestrator's, as upstream ships it
# checkov:skip=CKV_DOCKER_3:Upstream zcashd's image kept as upstream ships it (it creates a zcashd user but does not switch to it); not a Ycash release artifact: the Ycash image is contrib/docker/ycashd/Dockerfile, which runs as uid 2001
FROM debian:12

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl gnupg2 \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://apt.z.cash/zcash.asc \
  | gpg --dearmor -o /usr/share/keyrings/zcash-keyring.gpg \
  && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/zcash-keyring.gpg] https://apt.z.cash/ bookworm main" \
     > /etc/apt/sources.list.d/zcash.list \
  && apt-get update

ARG ZCASH_VERSION=
# The empty string for ZCASH_VERSION will install the apt default version,
# which should be the latest stable release. To install a specific
# version, pass `--build-arg 'ZCASH_VERSION=<version>'` to `docker build`.

RUN if [ -z "$ZCASH_VERSION" ]; \
    then apt-get install -y zcash; \
    else apt-get install -y zcash=$ZCASH_VERSION; \
    fi \
  && zcashd --version \
  && rm -rf /var/lib/apt/lists/*

ARG ZCASHD_USER=zcashd
ARG ZCASHD_UID=2001

RUN useradd --home-dir "/srv/$ZCASHD_USER" \
            --shell /bin/bash \
            --create-home \
            --uid "$ZCASHD_UID" \
            "$ZCASHD_USER"

RUN mkdir -p "/srv/$ZCASHD_USER/.zcash/" \
    && touch "/srv/$ZCASHD_USER/.zcash/ycash.conf" \
    && chown -R zcashd "/srv/$ZCASHD_USER"

WORKDIR "/srv/$ZCASHD_USER"
ENV HOME="/srv/$ZCASHD_USER"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

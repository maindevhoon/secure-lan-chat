FROM python:3.13-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

FROM base AS application
RUN mkdir /data /client /keys && chown 10001:10001 /data /client /keys
COPY lanchat ./lanchat
USER 10001:10001
CMD ["python", "-m", "lanchat.server"]

FROM base AS lab
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ns2 openssl tcl8.6 tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*
COPY lanchat ./lanchat
COPY lab ./lab
COPY tests ./tests
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]

FROM base AS certs
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY lab/certs.sh /usr/local/bin/chat-certs
ENTRYPOINT ["sh", "/usr/local/bin/chat-certs"]

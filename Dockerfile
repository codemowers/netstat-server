FROM ubuntu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yqq python3-scapy python3-pip
RUN pip3 install sanic kubernetes_asyncio cachetools
LABEL name="codemowers/netstat-server" \
      version="rc" \
      maintainer="Lauri Võsandi <lauri@codemowers.io>"
ENV PYTHONUNBUFFERED=1
ADD app /app
ENTRYPOINT /app/app.py

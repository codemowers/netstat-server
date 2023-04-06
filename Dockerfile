FROM python:alpine AS build
RUN apk add --no-cache gcc make musl-dev linux-headers git \
 && pip3 wheel --wheel-dir=/wheels \
      sanic kubernetes_asyncio
FROM python:alpine
COPY --from=build /wheels /wheels
RUN pip3 install --no-index /wheels/*.whl && rm -Rfv /wheels
LABEL name="codemowers/netstat-server" \
      version="rc" \
      maintainer="Lauri Võsandi <lauri@codemowers.io>"
ENV PYTHONUNBUFFERED=1
ADD app /app
ENTRYPOINT /app/app.py

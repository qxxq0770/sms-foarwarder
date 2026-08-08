FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app && \
    mkdir -p /data && chown app:app /data

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app app ./app
ENV PYTHONPATH=/app

USER app
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM runtime AS test
USER root
COPY requirements-test.txt ./
COPY tests ./tests
RUN pip install --no-cache-dir -r requirements-test.txt
USER app
CMD ["pytest", "-q", "-p", "no:cacheprovider"]

FROM runtime AS production

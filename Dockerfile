# syntax=docker/dockerfile:1

# python:3.6 reached end of life in December 2021 and stopped receiving
# security patches; it also could not run this code.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so that application edits do not invalidate this layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wsgi.py ./

# The application never needs to write to the filesystem, so it runs as an
# unprivileged user and the container can be started with --read-only.
RUN useradd --system --no-create-home --uid 10001 sspr \
    && chown -R root:root /app && chmod -R a-w /app
USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)"

# Flask's development server is never used here. Secrets come from the
# environment at run time, never baked into the image.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--threads", "4", \
     "--timeout", "45", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--forwarded-allow-ips", "*", \
     "wsgi:app"]

# Build context = the auth-package folder root:
#   docker build -f examples/demo_service/Dockerfile .
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv

# Install lexi_auth from source. In your real services you'd instead have in requirements.txt:
#   lexi-auth @ git+https://github.com/<your-org>/auth-package.git@v0.1.0
COPY pyproject.toml README.md /pkg/
COPY src /pkg/src
RUN pip install /pkg "uvicorn[standard]>=0.30"

COPY examples/demo_service/main.py ./main.py
RUN useradd --uid 10001 app
USER app
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]

FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Fix: Create symlink so Python can find the native library
RUN find / -name "libzklink_sdk.so" 2>/dev/null | head -1 | xargs -I{} cp {} /usr/local/lib/ && \
    ldconfig || true

COPY signer_service.py .

ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me
ENV LD_LIBRARY_PATH=/usr/local/lib

EXPOSE 8099
CMD ["python", "signer_service.py"]

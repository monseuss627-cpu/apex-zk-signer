FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Debug: find all zklink files
RUN echo "=== Finding zklink files ===" && \
    find / -name "*zklink*" -type f 2>/dev/null && \
    echo "=== Finding .so files in site-packages ===" && \
    find /usr/local/lib/python3.11/site-packages -name "*.so" 2>/dev/null && \
    echo "=== Trying import ===" && \
    python -c "import sys; sys.path.insert(0,'/usr/local/lib/python3.11/site-packages/apexomni/pc/linux_x86'); import zklink_sdk; print('SUCCESS')" 2>&1 || true

# Copy all .so files to /usr/local/lib
RUN find /usr/local/lib/python3.11/site-packages -name "libzklink_sdk*" -exec cp {} /usr/local/lib/ \; && \
    ldconfig 2>/dev/null || true

COPY signer_service.py .

ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/python3.11/site-packages/apexomni/pc/linux_x86

EXPOSE 8099
CMD ["python", "signer_service.py"]

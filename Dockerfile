FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed by the native .so
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgcc-s1 libstdc++6 libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Debug: test the import at build time
RUN python -c "from apexomni import zklink_sdk; print('BUILD: zklink_sdk loaded OK')" 2>&1 || \
    python -c "import ctypes, glob; files=glob.glob('/usr/local/lib/python3.11/site-packages/**/libzklink*', recursive=True); print('Found:', files); [print(ctypes.cdll.LoadLibrary(f)) for f in files]" 2>&1 || true

COPY signer_service.py .

ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me
ENV LD_LIBRARY_PATH=/usr/local/lib/python3.11/site-packages/apexomni/pc/linux_x86:/usr/local/lib

EXPOSE 8099
CMD ["python", "signer_service.py"]

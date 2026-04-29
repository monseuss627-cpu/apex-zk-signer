FROM python:3.11

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libgcc-s1 libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Verify the SDK loads at build time
RUN python -c "from apexpro import zklink_sdk; print('zklink_sdk loaded OK')"

COPY signer_service.py .

ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me

EXPOSE 8099
CMD ["python", "signer_service.py"]

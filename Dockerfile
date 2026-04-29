FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY signer_service.py .
ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me
EXPOSE 8099
CMD ["python", "signer_service.py"]

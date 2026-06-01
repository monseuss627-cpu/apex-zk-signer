FROM python:3.11-slim

WORKDIR /app

# Required for some native crypto deps used by apexomni
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libssl-dev libffi-dev curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY paisley_gittins.py .

ENV PORT=8099
EXPOSE 8099

CMD ["uvicorn", "paisley_gittins:app", "--host", "0.0.0.0", "--port", "8099"]
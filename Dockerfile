FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir ecdsa mpmath sympy eth-account

# Test import but don't fail the build
RUN python -c "from apexpro import zklink_sdk; print('OK')" 2>&1 || echo "SDK import failed at build - will retry at runtime"

COPY signer_service.py .

ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me

EXPOSE 8099
CMD ["python", "signer_service.py"]
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# Copy requirements specifically from the proxy directory
COPY proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application source code
COPY . .

CMD ["uvicorn", "proxy.proxy:app", "--host", "0.0.0.0", "--port", "8000"]

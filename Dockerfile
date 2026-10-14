FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.1"
COPY codshield ./codshield
CMD ["uvicorn", "codshield.api:app", "--host", "0.0.0.0", "--port", "8000"]

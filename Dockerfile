FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .
ENV PORT=8080
EXPOSE 8080

# Set database URI to mounted directory
ENV SQLITE_PATH=/data/sboms.db

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]

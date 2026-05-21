FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY entrypoint.sh /entrypoint.sh
COPY entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.sh

# Run as non-root for least privilege.
RUN useradd --create-home --shell /bin/bash --uid 10001 app \
    && chown -R app:app /app
USER app

ENTRYPOINT ["python3", "/entrypoint.py"]

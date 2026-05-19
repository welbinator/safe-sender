FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY entrypoint.sh /entrypoint.sh
COPY entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["python3", "/entrypoint.py"]

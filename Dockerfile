FROM python:3.7-slim-buster
WORKDIR /opt/
COPY . /opt/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

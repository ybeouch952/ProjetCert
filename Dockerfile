FROM python:3.7

WORKDIR /app

COPY main.py /app
COPY cert_pem.pem /app/

RUN apt-get update && \
    apt-get install -y openssl && \
    pip install datetime dnspython requests

CMD ["python", "main.py"]





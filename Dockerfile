FROM python:3.7-buster

RUN apt update && apt install -y git

WORKDIR /usr/src

RUN git clone https://github.com/fabian-hk/nassl.git

WORKDIR /usr/src/nassl

RUN git checkout tls_profiler

RUN pip install invoke requests

RUN invoke build.all

RUN pip install .

WORKDIR /usr/src/yesses

COPY requirements.txt ./
RUN pip install requests && pip install --no-cache-dir -r requirements.txt


FROM python:3.7-slim-buster
RUN apt update && apt install -y nmap libmagic1

COPY --from=0 /usr/local/lib/python3.7/site-packages /usr/local/lib/python3.7/site-packages

WORKDIR /usr/src/yesses

COPY . .

ENTRYPOINT [ "python", "/usr/src/yesses/run.py" ]
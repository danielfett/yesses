FROM python:3.8-slim-buster
RUN apt update && apt install -y nmap libmagic1 git-core

ADD . /usr/src/yesses
WORKDIR /usr/src/yesses
RUN pip install .

ENTRYPOINT [ "python", "/usr/src/yesses/yesses/bin/run.py" ]

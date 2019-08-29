FROM python:3

WORKDIR /usr/src/bogosec

COPY requirements.txt ./
RUN pip install requests && pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./run.py" ]
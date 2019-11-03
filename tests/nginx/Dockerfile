FROM debian:stretch-slim

RUN apt update && apt install -y nginx

COPY ./html /var/www/html

CMD ["nginx", "-g", "daemon off;"]

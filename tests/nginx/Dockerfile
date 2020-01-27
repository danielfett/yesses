FROM nginx:1.17.7

COPY nginx/default.conf /etc/nginx/conf.d/default.conf

COPY nginx/dhparams2048.pem /etc/ssl/dhparams2048.pem

COPY certificates/ecdsa_ca_cert.pem /etc/ssl/ecdsa_ca_cert.pem

COPY certificates/intermediate_key.pem /etc/ssl/tls_key.pem
COPY certificates/intermediate_cert.pem /etc/ssl/tls_cert.pem

COPY nginx/html /usr/share/nginx/html

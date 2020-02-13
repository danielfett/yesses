FROM php:7.2.25-apache

WORKDIR /workdir

RUN apt update && apt install -y git unzip
COPY laravel/composer-setup.php .
RUN php composer-setup.php
RUN php composer.phar create-project --prefer-dist laravel/laravel instance
RUN chown -R www-data:www-data /workdir/instance

COPY laravel/000-default.conf /etc/apache2/sites-available/000-default.conf
RUN a2enmod rewrite
RUN a2enmod ssl
RUN a2enmod headers

COPY certificates/modern_key.pem /usr/local/apache2/conf/tls_key.pem
COPY certificates/modern_cert.pem /usr/local/apache2/conf/tls_cert.pem

COPY laravel/laravel/env instance/.env
COPY laravel/laravel/web.php instance/routes/
COPY laravel/laravel/TestController.php instance/app/Http/Controllers/
COPY laravel/laravel/welcome.blade.php instance/resources/views/

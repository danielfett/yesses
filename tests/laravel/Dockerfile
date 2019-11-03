FROM php:7.2-apache

WORKDIR /workdir

RUN apt update && apt install -y git
COPY composer-setup.php .
RUN php composer-setup.php
RUN php composer.phar create-project --prefer-dist laravel/laravel instance
RUN chown -R www-data:www-data /workdir/instance

COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
RUN a2enmod rewrite

COPY laravel/.env instance/
COPY laravel/web.php instance/routes/
COPY laravel/TestController.php instance/app/Http/Controllers/
COPY laravel/welcome.blade.php instance/resources/views/

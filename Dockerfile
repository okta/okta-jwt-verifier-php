FROM php:7.2-cli-stretch

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

COPY . /app
WORKDIR /app

RUN composer install


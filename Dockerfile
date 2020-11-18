FROM php:7.2-cli-stretch

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

RUN apt-get update
RUN apt-get install -y zip git

RUN pecl install xdebug-2.9.8 && docker-php-ext-enable xdebug

COPY . /app
WORKDIR /app

RUN composer install


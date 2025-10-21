FROM php:8.1-apache

# Install MySQL extension
RUN docker-php-ext-install pdo pdo_mysql

# Copy aplikasi
COPY . /var/www/html/

# Enable Apache modules
RUN a2enmod rewrite headers

# Set ServerName untuk menghilangkan warning
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Set working directory
WORKDIR /var/www/html

# Expose port
EXPOSE 80

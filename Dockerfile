FROM php:8.1-apache

# Install MySQL extension
RUN docker-php-ext-install pdo pdo_mysql

# Enable Apache modules
RUN a2enmod rewrite headers

# Set ServerName untuk menghilangkan warning
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Enable .htaccess override
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Copy aplikasi
COPY . /var/www/html/

# Set working directory
WORKDIR /var/www/html

# Expose port
EXPOSE 80

CMD ["apache2-foreground"]
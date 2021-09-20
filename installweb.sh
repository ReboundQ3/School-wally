#!/bin/bash
#rootcheck
rootcheck () {
    if [ $(id -u) != "0" ]
    then
        sudo "$0" "$@"
        exit $?
    fi
}
# Introductie
    echo "$(tput setaf 2)########################################################################"
    echo "$(tput setaf 2)####$(tput setaf 7)              Welkom bij Koen's Webapp installer$(tput setaf 2)               #####"
    echo "$(tput setaf 2)####$(tput setaf 7)     met behulp van dit script wordt Apache2 geninstalleerd$(tput setaf 2)    #####"
    echo "$(tput setaf 2)####$(tput setaf 7)        en een cloud oplossing in de vorm van Nextcloud$(tput setaf 2)        #####"
    echo "$(tput setaf 2)####$(tput setaf 7)             of als je liever Nginx wil kan dat$(tput setaf 2)                #####"
    echo "$(tput setaf 2)########################################################################"$(tput setaf 7)
    read -p "#> Wil je de instalatie starten? [Y/N] " -n 1 -r
    echo #niets
    if [[ $REPLY =~ ^[Yy]$ ]]
        then 
        echo "#> Installatie gestart [$(tput setaf 2)✓$(tput setaf 7)]"
        sleep 2
        else
        echo "#> Insallatie afgebroken [$(tput setaf 1)✗$(tput setaf 7)]"
        sleep 2
        exit
    fi
    read -p "#> Wil je (A)pache of (N)ginx installeren? [A/N] " -n 1 -r
    echo #niets
        if [[ $REPLY =~ ^[Aa]$ ]]
        then
        echo "#> Apache Geselecteerd [$(tput setaf 2)✓$(tput setaf 7)]"
        selectapache=true
        sleep 2
        else
        echo "#> Nginx Geselecteerd [$(tput setaf 2)✓$(tput setaf 7)]"
        selectnginx=true
        sleep 2
    fi
    read -p "#> Wil je Fail2ban erbij installeren? [Y/N] " -n 1 -r
    echo #niets
        if [[ $REPLY =~ ^[Yy]$ ]]
        then
        echo "#> Fail2ban Geselecteerd [$(tput setaf 2)✓$(tput setaf 7)]"
        selectfail2ban=true
        sleep 2
        else
        echo "#> Fail2ban niet Geselecteerd [$(tput setaf 1)✗$(tput setaf 7)]"
        selectfail2ban=false
        sleep 2
    fi

# Apt checks en installaties
echo "####################    Softwaredetectie Gestart    ####################"

    #Apache
    if [ "$selectapache" == true ]; then
        if command -v apache2 >/dev/null 2>&1 ; then
         echo "#> Apache2 [$(tput setaf 2)✓$(tput setaf 7)]"
         install_apache2=false
         apache2installed=true
        else
        echo "#> Apache2 [$(tput setaf 1)✗$(tput setaf 7)]"
        install_apache2=true
        fi
    fi

    #Nginx
    if [ "$selectnginx" == true ]; then
        if command -v nginx >/dev/null 2>&1 ; then
         echo "#> Nginx [$(tput setaf 2)✓$(tput setaf 7)]"
         install_nginx=false
         Nginxinstalled=true
        else
        echo "#> Nginx [$(tput setaf 1)✗$(tput setaf 7)]"
        install_nginx=true
        fi
    fi 
    
    #MariaDB
    if command -v mariadb >/dev/null 2>&1 ; then
    echo "#> mariadb [$(tput setaf 2)✓$(tput setaf 7)]" 
    mariadb_install=true
    sleep 2
        else
         echo "#> mariadb [$(tput setaf 1)✗$(tput setaf 7)]"
         mariadb_install=false
    fi

    #PHP stack
    if command -v php >/dev/null 2>&1 ; then
    echo "#> PHP [$(tput setaf 2)✓$(tput setaf 7)]" 
    PHP_install=true
    sleep 2
        else
         echo "#> PHP [$(tput setaf 1)✗$(tput setaf 7)]"
         PHP_install=false
    fi

    #Fail2ban
    if [ "$selectfail2ban" == true ]; then
        fail2banonline=$(pgrep fail2ban | wc -l);
        if [ "$fail2banonline" -ne 1 ] ; then
         echo "#> Fail2ban [$(tput setaf 2)✓$(tput setaf 7)]"
        else
        echo "#> Fail2ban [$(tput setaf 1)✗$(tput setaf 7)]"
        install_fail2ban=false
        fi
    fi

# Alle installaties die nog gedaan moeten worden als die niet al geinstaleerd zijn
echo "###################    Benodigdheden installeren    ####################"   
    if [ "$install_apache2" = true ]; then
        apt install apache2 -y &> /dev/null
        echo "#> Apache2 Geinstaleerd[$(tput setaf 2)✓$(tput setaf 7)]"
        apache2installed=true
    fi

    if [ "$install_nginx" = true ]; then
        apt install nginx -y &> /dev/null
        echo "#> Nginx Geinstaleerd[$(tput setaf 2)✓$(tput setaf 7)]"
        Nginxinstalled=true
    fi

    if [ "$mariadb_install" = false ] ; then
        apt install mariadb-server -y &> /dev/null
        echo "#> mariadb Geinstaleerd[$(tput setaf 2)✓$(tput setaf 7)]"
        mariadbinstalled=true
    fi

    if [ "$PHP_install" = false ] ; then
        apt install php7.4-gd php7.4-mysql php7.4-curl php7.4-mbstring php7.4-intl php7.4-gmp php7.4-bcmath php-imagick php7.4-xml php7.4-zip -y &> /dev/null
        apt install libapache2-mod-php7.4 -y &> /dev/null
        echo "#> PHP Geinstaleerd[$(tput setaf 2)✓$(tput setaf 7)]"
        phpinstalled=true
    fi

    if [ "$install_fail2ban" = false ] ; then
        apt install fail2ban -y &> /dev/null
        echo "#> mariadb Geinstaleerd[$(tput setaf 2)✓$(tput setaf 7)]"
        fail2baninstalled=true
    fi

# SQL setup
echo "#######################    SQL-Setup gestart    ########################"
    
    #kijken of sql online is
    sql_online=$(pgrep mysql | wc -l);
    if [ "$sql_online" -ne 1 ];
    then
        echo "#> MySQL is offline [$(tput setaf 1)✗$(tput setaf 7)]";
        sudo service mysql start
        echo "#> MySQL starten [$(tput setaf 2)✓$(tput setaf 7)]";
        sleep 2
        echo "#> MySQL user "Nextcloud" aanmaken"
        sudo mysql -e"CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'nextcloud123'; CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost'; FLUSH PRIVILEGES;"
        echo "#> User "Nextcloud" aangemaakt [$(tput setaf 2)✓$(tput setaf 7)]"
    else
        echo "#> MySQL is al gestart [$(tput setaf 2)✓$(tput setaf 7)]";
        sleep 2
        echo "#> MySQL user "Nextcloud" aanmaken"
        sudo mysql -e"CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'nextcloud123'; CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost'; FLUSH PRIVILEGES;"
        echo "#> User "Nextcloud" aangemaakt [$(tput setaf 2)✓$(tput setaf 7)]"
    fi

#Nextcloud download
echo "#######################    Nextcloud setup gestart    ########################"
    wget https://download.nextcloud.com/server/releases/nextcloud-21.0.2.tar.bz2
    tar -xjvf nextcloud-21.0.2.tar.bz2
    cd ~
    mkdir /var/www/nextcloud
    mv ~/nextcloud/* /var/www/nextcloud
    sudo chmod -R ugo+rw * /var/www/nextcloud
    chown www-data:www-data /var/www/nextcloud -R
    rm ~/nextcloud -f -r
echo "##############################################################################"
echo "#> Wat moet de domain name worden? (<domain>.local)"
read domainname
ip_apashe=$(hostname -i)
echo "#> domain name = $domainname.local"
    if [ "$apache2installed" = true ]; then
    rm /etc/apache2/sites-available/* -f -r
    rm /etc/apache2/sites-enabled/* -f -r
        echo '<VirtualHost *:443>
   ServerName '$ip_apashe'
   DocumentRoot /var/www/nextcloud/

   SSLEngine on
   SSLCertificateFile /etc/ssl/certs/nextcloudapache.crt
   SSLCertificateKeyFile /etc/ssl/private/nextcloudapache.key
</VirtualHost>

<VirtualHost *:80>
  DocumentRoot /var/www/nextcloud/
  ServerName  '$ip_apashe'
  redirect / https://'$ip_apashe'/
  Alias /nextcloud "var/www/nextcloud/"
  
  <Directory /var/www/nextcloud/>
    Require all granted
    AllowOverride All
    Options FollowSymLinks MultiViews
    Satisfy Any
    SetEnv HOME /var/www/nextcloud/
    SetEnv HTTP_HOME /var/www/nextcloud/

    <IfModule mod_dav.c>
      Dav off
    </IfModule>
  </Directory>
</VirtualHost>' > /etc/apache2/sites-available/nextcloud.conf
echo "#> Nextcloud Apache config erin geplakt"
    a2ensite nextcloud.conf
    a2enmod rewrite
    a2enmod headers
    a2enmod env
    a2enmod dirsa2enmod mime
    a2enmod setenvif
    service apache2 restart
    a2enmod ssl
    a2ensite nextcloud
    service apache2 reload

# De boel beveiligen
    echo "#> Nu gaan we een certificaat aanmaken voor de locale website, dit houdt in wat details om in te vullen"
    read -t 5 -n 1 -s -r -p "#> Druk op een toets om verder te gaan"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nextcloudapache.key -out /etc/ssl/certs/nextcloudapache.crt
    service apache2 reload
    echo "##############################################################################"
    echo "                               SSL Self Signed!                               "
    echo "##############################################################################"


    fi
#Nginx config erin plakken
    if [ "$Nginxinstalled" = true ]; then
        #eerst een SSL Certificaat maken
        ufw allow 'Nginx Full'
        echo "#> Nu gaan we eerst certificaat aanmaken voor de locale website, dit houdt in wat details om in te vullen"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
        openssl dhparam -out /etc/nginx/dhparam.pem 1024
        echo 'ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;' > /etc/nginx/snippets/self-signed.conf

        echo 'ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off; # Requires nginx >= 1.5.9
ssl_stapling on; # Requires nginx >= 1.3.7
ssl_stapling_verify on; # Requires nginx => 1.3.7
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable strict transport security for now. You can uncomment the following
# line if you understand the implications.
# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";' > /etc/nginx/snippets/ssl-params.conf

#Even checken of dependencies er zijn
        sudo apt install imagemagick php-imagick php7.4-common php7.4-mysql php7.4-fpm php7.4-gd php7.4-json php7.4-curl  php7.4-zip php7.4-xml php7.4-mbstring php7.4-bz2 php7.4-intl php7.4-bcmath php7.4-gmp -y &> /dev/null
        ip=$(hostname -i)
        touch /etc/nginx/conf.d/nextcloud.conf
#de werkelijke config erin plakken
        echo 'upstream php-handler {
    server 127.0.0.1:9000;
    server unix:/var/run/php/php7.4-fpm.sock;
}

server {
    listen 80;
    listen [::]:80;
    server_name '$ip';

    # Enforce HTTPS
    return 302 https://$server_name$request_uri;
}

server {
    listen 443      ssl http2;
    listen [::]:443 ssl http2;
    include snippets/self-signed.conf;
    include snippets/ssl-params.conf;

    server_name '$ip';

    # Use Mozillas guidelines for SSL/TLS settings
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
    ssl_certificate     /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;

    # HSTS settings
    # WARNING: Only add the preload option once you read about
    # the consequences in https://hstspreload.org/. This option
    # will add the domain to a hardcoded list that is shipped
    # in all major browsers and getting removed from this list
    # could take several months.
    #add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;

    # set max upload size
    client_max_body_size 512M;
    fastcgi_buffers 64 4K;

    # Enable gzip but do not remove ETag headers
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    # Pagespeed is not supported by Nextcloud, so if your server is built
    # with the `ngx_pagespeed` module, uncomment this line to disable it.
    #pagespeed off;

    # HTTP response headers borrowed from Nextcloud `.htaccess`
    add_header Referrer-Policy                      "no-referrer"   always;
    add_header X-Content-Type-Options               "nosniff"       always;
    add_header X-Download-Options                   "noopen"        always;
    add_header X-Frame-Options                      "SAMEORIGIN"    always;
    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
    add_header X-Robots-Tag                         "none"          always;
    add_header X-XSS-Protection                     "1; mode=block" always;

    # Remove X-Powered-By, which is an information leak
    fastcgi_hide_header X-Powered-By;

    # Path to the root of your installation
    root /var/www/nextcloud;

    # Specify how to handle directories -- specifying `/index.php$request_uri`
    # here as the fallback means that Nginx always exhibits the desired behaviour
    # when a client requests a path that corresponds to a directory that exists
    # on the server. In particular, if that directory contains an index.php file,
    # that file is correctly served; if it doesnt, then the request is passed to
    # the front-end controller. This consistent behaviour means that we dont need
    # to specify custom rules for certain paths (e.g. images and other assets,
    # `/updater`, `/ocm-provider`, `/ocs-provider`), and thus
    # `try_files $uri $uri/ /index.php$request_uri`
    # always provides the desired behaviour.
    index index.php index.html /index.php$request_uri;

    # Rule borrowed from `.htaccess` to handle Microsoft DAV clients
    location = / {
        if ( $http_user_agent ~ ^DavClnt ) {
            return 302 /remote.php/webdav/$is_args$args;
        }
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Make a regex exception for `/.well-known` so that clients can still
    # access it despite the existence of the regex rule
    # `location ~ /(\.|autotest|...)` which would otherwise handle requests
    # for `/.well-known`.
    location ^~ /.well-known {
        # The rules in this block are an adaptation of the rules
        # in `.htaccess` that concern `/.well-known`.

        location = /.well-known/carddav { return 301 /remote.php/dav/; }
        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

        location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }
        location /.well-known/pki-validation    { try_files $uri $uri/ =404; }

        # Let Nextclouds API for `/.well-known` URIs handle all other
        # requests by passing them to the front-end controller.
        return 301 /index.php$request_uri;
    }

    # Rules borrowed from `.htaccess` to hide certain paths from clients
    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)                { return 404; }

    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
    # which handle static assets (as seen below). If this block is not declared first,
    # then Nginx will encounter an infinite rewriting loop when it prepends `/index.php`
    # to the URI, resulting in a HTTP 500 error response.
    location ~ \.php(?:$|/) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        set $path_info $fastcgi_path_info;

        try_files $fastcgi_script_name =404;

        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;

        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
        fastcgi_param front_controller_active true;     # Enable pretty urls
        fastcgi_pass php-handler;

        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
    }

    location ~ \.(?:css|js|svg|gif)$ {
        try_files $uri /index.php$request_uri;
        expires 6M;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Dont log access to assets
    }

    location ~ \.woff2?$ {
        try_files $uri /index.php$request_uri;
        expires 7d;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Dont log access to assets
    }

    # Rule borrowed from `.htaccess`
    location /remote {
        return 301 /remote.php$request_uri;
    }

    location / {
        try_files $uri $uri/ /index.php$request_uri;
    }
} '> /etc/nginx/conf.d/nextcloud.conf

echo '# Default server configuration
#
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	# SSL configuration
	#
	# listen 443 ssl default_server;
	# listen [::]:443 ssl default_server;
	#
	# Note: You should disable gzip for SSL traffic.
	# See: https://bugs.debian.org/773332
	#
	# Read up on ssl_ciphers to ensure a secure configuration.
	# See: https://bugs.debian.org/765782
	#
	# Self signed certs generated by the ssl-cert package
	# Dont use them in a production server!
	#
	# include snippets/snakeoil.conf;

	root /var/www/nextcloud;

	# Add index.php to the list if you are using PHP
	index index.php index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

	# pass PHP scripts to FastCGI server
	#
	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
	
		# With php-fpm (or other unix sockets):
		fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
		# With php-cgi (or other tcp sockets):
		#fastcgi_pass 127.0.0.1:9000;
	}

	# deny access to .htaccess files, if Apaches document root
	# concurs with nginxs one
	#
	#location ~ /\.ht {
	#	deny all;
	#}
}


# Virtual Host configuration for example.com
#
# You can move that to a different file under sites-available/ and symlink that
# to sites-enabled/ to enable it.
#
#server {
#	listen 80;
#	listen [::]:80;
#
#	server_name example.com;
#
#	root /var/www/example.com;
#	index index.html;
#
#	location / {
#		try_files $uri $uri/ =404;
#	}
#}' > /etc/nginx/sites-available/default

systemctl restart nginx
    fi
echo "$(tput setaf 2)#########################################################################"
echo "$(tput setaf 2)# $(tput setaf 7)Installatie voltooid, ga nu naar $ip:80 of 127.0.0.1:80 op je machine$(tput setaf 2)    #"
echo "$(tput setaf 2)# $(tput setaf 7)ga nu naar $ip:80 of 127.0.0.1:80 op je machine$(tput setaf 2)                          #"
echo "$(tput setaf 2)# $(tput setaf 7)om de configuratie te voltooien, dit houd in een admin account maken$(tput setaf 2)  #"
echo "$(tput setaf 2)# $(tput setaf 7)en de database gegevens invoeren, hier volgen de gegevens om de$(tput setaf 2)       #"
echo "$(tput setaf 2)# $(tput setaf 7)database mee te configureren$(tput setaf 2)                                          #"
echo "$(tput setaf 2)# $(tput setaf 7)Gebruiker Database: nextcloud$(tput setaf 2)                                         #"
echo "$(tput setaf 2)# $(tput setaf 7)wachtwoord Database: nextcloud123  (je lokale 192 adres werkt ook!)$(tput setaf 2)   #"
echo "$(tput setaf 2)# $(tput setaf 7)naam Database: nextcloud$(tput setaf 2)                                              #"
echo "$(tput setaf 2)# $(tput setaf 7)Databaseserver: localhost         (mocht deze er nog niet staan)$(tput setaf 2)      #"
echo "$(tput setaf 2)#########################################################################"
echo "$(tput setaf 2)#                           $(tput setaf 7)Nog een fijne dag!$(tput setaf 2)                          #"
echo "$(tput setaf 2)#########################################################################"$(tput setaf 7)
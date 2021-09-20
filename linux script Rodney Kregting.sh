#!/bin/bash
clear
herstarten=y
while [ $herstarten == "y" ]
do
#Introductie
echo "Welkom bij de installatie script voor de nextcloud server!"
echo ""
#Keuze voor de Webserver
echo "Installatie voor een van de 3 webservers"
echo "Er is keuze uit 3 webservers Apache, Lighttpd, Nginx."
echo -n "welke webserver wil je? (apache, lighttpd, nginx): "; read webservers
echo ""

        function Install-web
        {
        echo "Er is gekozen voor "$webservers"."
        echo "Instalatie "$webservers" wordt gestart."
        }

        function message-web
        {
        echo ""$webservers" is al geinstaleerd."
        }

if [ $webservers == "apache" ];
        then
          Install-web
          systemctl start apache2
           if ( systemctl -q is-active apache2 == "inactive" )
             then
              message-web
               else
                apt install apache2
                systemctl stop apache2.service
                systemctl start apache2.service
                systemctl enable apache2.service
                fi
fi

if [ $webservers == "lighttpd" ];
        then
          Install-web
          systemctl start lighttpd
           if ( systemctl -q is-active lighttpd == "inactive" )
             then
              message-web
               else
                apt install lighttpd
                systemctl stop lighttpd.service
                systemctl start lighttpd.service
                systemctl enable lighttpd.service
                fi
fi

if [ $webservers == "nginx" ];
        then
          Install-web
          systemctl start nginx
           if ( systemctl -q is-active nginx == "inactive" )
             then
              message-web
               else
                apt install nginx
                systemctl stop nginx.service
                systemctl start nginx.service
                systemctl enable nginx.service
                fi
fi

#Vul hier je domainnaam in!
echo -n "Geef de gewenste domein naam op : "; read domainname
echo ""

#keuze van Database
echo "Installatie voor een van de 2 databases"
echo "Er is keuze uit 2 databasen mariadb, mysql."
echo -n "welke database wil je? (mariadb, mysql.): "; read database
echo ""

        function Install-database
        {
        echo "Er is gekozen voor "$database"."
        echo "Instalatie "$database" wordt gestart."
        }

        function message-database
        {
        echo ""$database" is al geinstalleerd."
        }

if [ $database == "mariadb" ];
        then
          Install-database
          systemctl start mariadb-server mariadb-client
           if ( systemctl -q is-active mariadb == "inactive" )
             then
              message-database
               else
                apt install mariadb-server mariadb-client
                systemctl stop mariadb.service
                systemctl start mariadb.service
                systemctl enable mariadb.service
                fi
fi
if [ $database == "mysql" ];
        then
          Install-database
          systemctl start mysql-server mysql-client
           if ( systemctl -q is-active mysql == "inactive" )
             then
              message-database
               else
                apt install mysql-server mysql-client
                systemctl stop mysql.service
                systemctl start mysql.service
                systemctl enable mysql.service
                fi

fi
#Kijk naar de download zip

echo ""

if [ -f "nextcloud-21.0.2.zip" ];
    	then
         echo "Het programma Nextcloud is al geinstalleerd"
    	  else
           wget https://download.nextcloud.com/server/releases/nextcloud-21.0.2.zip
fi
#check unzip
if [ -f "/usr/bin/unzip" ];
        then
         echo "unzip is al geinstalleerd"
          else
           apt install unzip
fi

	unzip nextcloud-21.0.2.zip
	mv nextcloud/ /var/www/

#permissies voor nextcloud
chown -r www-data:www-data /var/www/nextcloud
a2dissite 000-default.conf
systemctl reload apache2


#Configuratie vragen
echo -n "Wilt u zelf de configuratie instellen van de webserver, database, nextcloud en PHP? (y/n):"; read config

#Config Apache
echo "config apache"

if [ $config == "y" ];
       then
	echo "Maak hier u configuratie bestand aan"
	echo "nano /etc/apache2/sites-available/nextcloud.conf"
	echo "Dit moet de configuratie worden"
	echo ""
	echo "<VirtualHost *:80>"
	echo 'DocumentRoot "/var/www/nextcloud"'
	echo "ServerName nextcloud"
	echo ""
	echo '<Directory "/var/www/nextcloud/">'
	echo "Options MultiViews FollowSymlinks"
	echo "AllowOverride All"
	echo "Order allow,deny"
	echo "Allow from all"
	echo "</Directory>"
	echo ""
	echo "TransferLog /var/log/apache2/nextcloud_access.log"
	echo "ErrorLog /var/log/apache2/nextcloud_error.log"
	echo ""
	echo "</VirtualHost>"
fi

if [ $config == "n" ];
	then
         rm -f /etc/apache2/sites-available/nextcloud.conf
	  touch /etc/apache2/sites-available/nextcloud.conf
           echo "<VirtualHost *:80>" >> /etc/apache2/sites-available/nextcloud.conf
           echo 'DocumentRoot "/var/www/nextcloud"' >> /etc/apache2/sites-available/nextcloud.conf
           echo "ServerName nextcloud" >> /etc/apache2/sites-available/nextcloud.conf
           echo "" >> /etc/apache2/sites-available/nextcloud.conf
           echo '<Directory "/var/www/nextcloud/">' >> /etc/apache2/sites-available/nextcloud.conf
           echo "Options MultiViews FollowSymlinks" >> /etc/apache2/sites-available/nextcloud.conf
           echo "AllowOverride All" >> /etc/apache2/sites-available/nextcloud.conf
           echo "Order allow,deny" >> /etc/apache2/sites-available/nextcloud.conf
           echo "Allow from all" >> /etc/apache2/sites-available/nextcloud.conf
           echo "</Directory>" >> /etc/apache2/sites-available/nextcloud.conf
           echo "" >> /etc/apache2/sites-available/nextcloud.conf
           echo "TransferLog /var/log/apache2/nextcloud_access.log" >> /etc/apache2/sites-available/nextcloud.conf
           echo "ErrorLog /var/log/apache2/nextcloud_error.log" >> /etc/apache2/sites-available/nextcloud.conf
           echo "" >> /etc/apache2/sites-available/nextcloud.conf
           echo "</VirtualHost>" >> /etc/apache2/sites-available/nextcloud.conf

fi

#config mariadb
echo "config van mariadb"
if [ $config =="y" ];
	then
	 echo "Vul dit dan in"
	 echo "sudo mariadb"
	 echo "CREATE DATABASE nextcloud"
	 echo "GRANT ALL PRIVILEGES ON Nextcloud.* TO 'Rodney'@'localhost' IDENTIFIED BY 'P0iuytrewq';"
	 echo "FLUSH PRIVILEGES;"
	 echo ""
fi

if [ $config == "n" ];
	then
	 mysql -e "CREATE DATABASE nextcloud"
	 mysql -e "GRANT ALL PRIVILEGES ON nextcloud.* TO 'Rodney'@'localhost' IDENTIFIED BY 'P0iuytrewq';"
	 mysql -e "FLUSH PRIVILEGES"
fi

#config nextcloud
echo "configuratie van nextcloud"
if [ $config == "y" ];
	then
	 echo "edit file"
	 echo "nano var/www/nextcloud/config/config.php"
	 echo "Voeg de aankomende regel toe"
	 echo "'memecache.local' => '\OC\Memcache\APCu',"
fi

if [ $config == "n" ];
        then
         sed -i "s/);/  'memcache.local' => '\OC\Memcache\APCu',/g" /var/www/nextcloud/config/config.php
         sed -i -e '$a);' /var/www/nextcloud/config/config.php

fi
#config php
echo "config php"

if [ $config == "y" ];
        then
         echo "edit file"
         echo "nano /etc/php/7.3/apache2/php.ini"
         echo "memory_limit = 512M"
         echo "upload_max_filesize = 200M"
         echo "max_execution_time = 360"
         echo "post_max_size = 200M"
         echo "date.timezone = Netherlands/Amsterdam"
         echo "opcache.enable=1"
         echo "opcache.interned_strings_buffer=8"
         echo "opcache.max_accelerated_files=10000"
         echo "opcache.memory_consumption=128"
         echo "opcache.save_comments=1"
         echo "opcache.revalidate_freq=1"
fi

if [ $config == "n" ];
        then
       	 sed -i 's/memory_limit = 128M/memory_limit = 512M/g' /etc/php/7.3/apache2/php.ini
       	 sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 200M/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/max_execution_time = 30/max_execution_time = 360/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/post_max_size = 8M/post_max_size = 200M/g' /etc/php/7.3/apache2/php.ini
         #sed 's/;date.timezone =/date.timezone = Netherlands/Amsterdam/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/;opcache.enable=1/opcache.enable=1/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/;opcache.interned_strings_buffer=8/opcache.interned_strings_buffer=8/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/;opcache.max_accelerated_files=10000/opcache.max_accelerated_files=10000/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/;opcache.memory_consumption=128/opcache.memory_consumption=128/g' /etc/php/7.2/apache2/php.ini
         sed -i 's/;opcache.save_comments=1/opcache.save_comments=1/g' /etc/php/7.3/apache2/php.ini
         sed -i 's/;opcache.revalidate_freq=2/opcache.revalidate_freq=1/g' /etc/php/7.3/apache2/php.ini
fi

sudo a2ensite nextcloud.conf
systemctl restart apache2

#php premissies
chmod 660 /var/www/nextcloud/config/config.php
chmod root:www-data /var/www/nextcloud/config/config.php


#Install fail2ban
	echo"hier installeer je fail2ban"
	sudo apt-get install -y fail2ban
	sudo systemctl start fail2ban
	sudo systemctl enable fail2ban
	

#Config Fail2ban
	echo "Dit is de configuratie van fail2ban"
	cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	sed -i 's/#ignoreip = 127.0.0.1/ignoreip = 127.0.0.1/g' /etc/fail2ban/jail.local
        sed -i 's/bantime  = 10m/bantime  = 300m/g' /etc/fail2ban/jail.local
        sed -i 's/findtime  = 10m/findtime  = 300m/g' /etc/fail2ban/jail.local
        sed -i 's/maxretry = 5/maxretry = 7/g' /etc/fail2ban/jail.local
        sed -i '247 i maxretry = 3' /etc/fail2ban/jail.local
        sed -i '248 i enable = true' /etc/fail2ban/jail.local
	sudo systemctl restart fail2ban
	
#Configuratie Firewall
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#Configuratie voor HTTPS/HTTP
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#Installeren van de SSL
	apt install openssl
        mkdir /etc/apache2/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/sslkey.key -out /etc/apache2/ssl/sslkey.crt
        a2ensite nextcloud.conf
        a2enmod ssl
        sed -i 's/80/443/g' /etc/apache2/sites-enabled/nextcloud.conf
        sed -i '4 i SSLEngine on' /etc/apache2/sites-enabled/nextcloud.conf
        sed -i '5 i SSLCertificateFile      /etc/apache2/ssl/sslkey.crt' /etc/apache2/sites-enabled/nextcloud.conf
        sed -i '6 i SSLCertificateKeyFile   /etc/apache2/ssl/sslkey.key' /etc/apache2/sites-enabled/nextcloud.conf
        a2ensite default-ssl
        a2dissite default-ssl.conf
        systemctl reload apache2.service

echo -n "Wil je het script opnieuw opstarten?(y/n)"; read herstarten
done
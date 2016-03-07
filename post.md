---
title: State of the art of a secure web deployment using Let's Encrypt & Nginx
html_title: State of the art of a secure web deployment using Let's Encrypt & Nginx
meta_desc: State of the art of a secure web deployment using Let's Encrypt & Nginx
intro: Securing a website is hard this why you should do, it how to do it and blah blah.
---

We will detail all the steps to get the best rating (A+) on the popular [Qualys SSL](https://www.ssllabs.com/ssltest/) and [securityheaders.io](https://securityheaders.io) analysers using an automated Let's Encrypt certificate. All backed by Nginx, our open source webserver of choice.

## Let's Encrypt overview

Let's Encrypt is a new open source, fully automated service that provides free SSL certificates. The Let's Encrypt root certificate is also well trusted by most [browsers](https://community.letsencrypt.org/t/which-browsers-and-operating-systems-support-lets-encrypt/4394).

Before starting, below are a few caveats which not everybody may be comfortable with:

* It's still in __beta__ phase.
* It requires root privileges.
* The client does not yet "officially" support Nginx (but it works flawlessly).
* It installs dependencies automatically (like [Augeas](http://augeas.net/), [gcc](https://gcc.gnu.org/), [Python](https://www.python.org/)).
* Throttling is enforced so you cannot request more than 5 certificates per week for a given domain.
* Certificate is valid for 90 days.

It's possible to get a certificate using other [alternate lightweight and less intrusive clients](https://community.letsencrypt.org/t/list-of-client-implementations/2103) however we won't cover them in this post.

The official documentation can be found [here](http://letsencrypt.readthedocs.org/en/latest/intro.html).

## Infrastructure setup

First we begin by spawning a new cloud instance. We're going to use [Exoscale](https://www.exoscale.ch) for this purpose. Exoscale is the leading Swiss cloud provider. Within their [portal](https://portal.exoscale.ch), we select our favorite Linux Ubuntu 14.04 flavour. For our demo a micro instance (512mb RAM, 1 Vcpu & 10GB disk) will be more than enough.

Within a few seconds our instance is available and ready for use:

![alt text](static/images/instance1.png "Our instance detailed view")

We take note of its IP address so we can proceed with the DNS setup. Luckily DNS zone hosting is only one click away within the management portal:

![alt text](static/images/dns1.png "DNS zone creation")

We create our zone "letsecure.me".

___N.B Put your own zone name here.___

Now we add a "A" record with the value of the ip address of our freshly spawned instance, as well as a "catch all" (wildcard) CNAME record:

![alt text](static/images/dns2.png "DNS record creation")

We're done with DNS records, don't forget to update the nameservers of your domain with the ones below:

* `ns1.exoscale.com`
* `ns1.exoscale.ch`
* `ns1.exoscale.net`
* `ns1.exoscale.io`

This change must be done from within your domain registrar administration console.

## Basic security hardening

Let's go back to our instance. Before beginning with the setup, we're going to apply a few elementary security best practices:

On the [firewall](https://portal.exoscale.ch/compute/firewalling) side, we allow only the required traffic by adding the rules below:

* 22 (SSH)
* 80 (HTTP)
* 443 (HTTPS)
* ICMP ping (not mandatory but convenient)

Our firewall is now configured. We can now login using the _ubuntu_ user and our [SSH key](https://community.exoscale.ch/documentation/compute/ssh-keypairs/). This isn't mandatory but highly recommended. Standard authentication with password is also supported.

The next thing we do is to apply all the software updates and reboot the instance with the following commands:

    sudo apt-get update && sudo apt-get dist-upgrade -y && sudo reboot

We log back in and enable the automatic security updates:

    sudo dpkg-reconfigure --priority=low unattended-upgrades

Looks good so far. If you're using SSH key authentication, __and only if so__, you may also disable the SSH password authentication:

    sudo sed -i 's|PasswordAuthentication yes|PasswordAuthentication no|g' /etc/ssh/sshd_config
    sudo service ssh restart

We suggest to installing [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) to prevent brute force SSH attacks (specifically if you're using password authentication):

    sudo apt-get install -y fail2ban

## Nginx Setup

Now we'll take care of Nginx. We're not going to install the package from the Ubuntu repository as we require features (like HTTP/2) that can only be found in the latest "mainline" release branch. We add the Nginx official repository using:

    curl http://nginx.org/keys/nginx_signing.key | sudo apt-key add -
    sudo echo "deb http://nginx.org/packages/mainline/ubuntu/ trusty nginx" > /etc/apt/sources.list.d/nginx_org_packages_mainline_ubuntu.list
    sudo apt-get update && apt-get install -y nginx

We create the target folder from where our wesite will be served:

    sudo mkdir /var/www/
    wget STE demo page from github repo
    tar -xvf /var/www/
    sudo chown -R www-data /var/www/

Remove Nginx default configuration:

    sudo rm /etc/nginx/conf.d/default.conf
    sudo touch /etc/nginx/conf.d/default.conf

And add the following Nginx configuration block in `/etc/nginx/conf.d/default.conf`, so Let's Encrypt client can create the temporary files required to authenticate the domain for which we're requesting the certificate:

    server {
        listen 80;
        server_name default_server;
        root /var/www/demo;
        location /.well-known/acme-challenge {
            default_type "text/plain";
        }
    }

Now we reload Nginx to apply our configuration change:

    nginx -t && sudo nginx -s reload

## Let's Encrypt setup

We're done with Nginx for the time being. Go for Let's Encrypt. We're going to clone its [GIT](https://github.com/letsencrypt/letsencrypt) repository:

    sudo apt-get install -y git
    git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt
    /opt/letsencrypt/letsencrypt-auto

Note that the setup script is installing all the required dependencies automatically.

Now we can request our certificate. You'll get prompted to provide your email address for the expiring notifications and accept the Terms:

    export DOMAINS="letsecure.me,www.letsecure.me"
    export DIR=/var/www/demo
    /opt/letsencrypt/letsencrypt-auto certonly --server https://acme-v01.api.letsencrypt.org/directory -a webroot --webroot-path=$DIR -d $DOMAINS

_N.B Put your own domain in the DOMAINS list._

Our cert has been issued and installed!

    IMPORTANT NOTES:
    - Congratulations! Your certificate and chain have been saved at
      /etc/letsencrypt/live/letsecure.me/fullchain.pem. Your cert will
      expire on 2016-XX-XX. To obtain a new version of the certificate in
      the future, simply run Let's Encrypt again.
    - Your account credentials have been saved in your Let's Encrypt
      configuration directory at /etc/letsencrypt. You should make a
      secure backup of this folder now. This configuration directory will
      also contain certificates and private keys obtained by Let's
      Encrypt so making regular backups of this folder is ideal.
    - If you like Let's Encrypt, please consider supporting our work by:

    Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate

Let's Encrypt configuration and certificates can be found under `/etc/letsencrypt`.

We add the following minimal Nginx configuration block in `/etc/nginx/conf.d/default.conf` so our website gets served over HTTPS:

    server {
        listen 443 ssl;
        server_name letsecure.me www.letsecure.me;
        root /var/www/demo;
        ssl_certificate /etc/letsencrypt/live/letsecure.me/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/letsecure.me/privkey.pem;
    }

_N.B replace the server name with your domain._

Let's reload nginx one more time:

    nginx -t &&  sudo nginx -s reload

Now point your web browser to https://YOURDOMAINHERE

The homepage should display now over HTTPS. \o/ 

We need to ensure that our certificate, which is valid for 90 days only, gets renewed automatically. We're going to use a small script and a crontab for this purpose:

    #!/bin/sh
    # This script renews all the Let's Encrypt certificates with a validity < 30 days

    if ! /opt/letsencrypt/letsencrypt-auto renew > /var/log/letsencrypt/renew.log 2>&1 ; then
        echo Automated renewal failed:
        cat /var/log/letsencrypt/renew.log
        exit 1
    fi
    nginx -t && nginx -s reload

This script can also be downloaded [here](https://raw.githubusercontent.com/llambiel/letsecureme/master/renewCerts.sh).

We add a daily cron that trigger our script:

    sudo crontab -e

and add the following line:

    @daily /path/to/renewCerts.sh

Now that our website is being served over HTTPS, let's check the grade we have using a default SSL configuration: https://www.ssllabs.com/ssltest/

The result's not so good. Let's pimp a bit our Nginx config to improve our rating:

## Nginx SSL hardening 

Remove the actual config in `/etc/nginx/conf.d/default.conf` and replace it by the block below:

    server {
        listen 80;
        listen 443 ssl http2;
        server_name yourdomain.com www.yourdomain.com;
         ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
         ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
         ssl_prefer_server_ciphers On;
         ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
         ssl_session_cache shared:SSL:128m;
         add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
         ssl_stapling on;
         ssl_stapling_verify on;
         resolver 8.8.8.8;
         root /var/www/demo;
         index index.html;

         location '/.well-known/acme-challenge' {
          default_type "text/plain";
            root        /var/www/demo;
          }

         location / {
                  if ($scheme = http) {
                    return 301 https://$server_name$request_uri;
                  }
         }
    }

_N.B replace the server name and SSL certificate paths with your domain._

And reload nginx:

    nginx -t && sudo nginx -s reload

Let's review some important config items that we've just added:

    listen 443 ssl http2;

With this directive, we tell Nginx to listen over SSL and also support the connection over the new [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) standard, if the client browser support / request it. Please note that HTTP/2 is SSL only

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

We disable old and weak SSLv2/SSLv3 protocols and allow only the TLS ones.

    ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
    ssl_prefer_server_ciphers On;

This is the cipher list we support. This list is in our opinion one of the most well balanced between security and support by older web browsers. We also ask Nginx to prefer our ciphers over the ones requested by the client.


    ssl_stapling on;
    ssl_stapling_verify on;

We enable OCSP stapling. OCSP stapling is well described in details [here](https://www.maxcdn.com/one/visual-glossary/ocsp-stapling/).

    add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";

Here we add a HTTP header instructing the client browser to force a HTTPS connection to our domain and __all our Subdomains for 1 year__. __Warning__ be careful here before applying it in production, you must ensure first that all your subdomains are being secured as well.

Let's re-test again our setup with [Qualys SSL](https://www.ssllabs.com/ssltest/):

![alt text](static/images/qualys2.png "Qualys SSL final check")

Hey, this looks much better now ! Our setup is now secured using an optimal SSL configuration, our first objective is achieved.

## Security headers hardening

Now, what about the content / behaviour of our website? [Scott Helme](https://securityheaders.io/about/) did create a great HTTP response headers [analyser](https://securityheaders.io/).

Let's get a step further and try to get a good grade on this analyser as well. Let's try on our current setup and see that the result is... not so good:

![alt text](static/images/securityheaders1.png "securityheaders.io first check")

_N.B ensure to test using HTTPS._

Again let's tune a bit our configuration by adding a few HTTP headers:

    add_header X-Content-Type-Options "nosniff" always;

The [X-Content-Type-Options](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options) header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type.

    add_header X-Frame-Options "SAMEORIGIN" always;

The [X-Frame-Options](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options) header tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking.

    add_header X-Xss-Protection "1";

The [X-Xss-Protection](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-xss-protection) header sets the configuration for the cross-site scripting filter built into most browsers.

    add_header Content-Security-Policy "default-src 'self'";

The Content-Security-Policy header defines approved sources of content that the browser may load. It can be an effective countermeasure to Cross Site Scripting (XSS) attacks. __WARNING__ This header must be carefully planned before deploying it on production website as it could easily break stuff and prevent a website to load it's content! Fortunately there is a "report mode" available which the browser to report any issue in the debug console but not actually block any content. This is very helpful to ensure a smooth deployment  of this header:

![alt text](static/images/reportmode.png "report mode")

The configuration of this policy is well described [here](https://scotthelme.co.uk/content-security-policy-an-introduction/)

The report mode can be enabled using:

    Content-Security-Policy-Report-Only instead of Content-Security-Policy

### Final Nginx configuration

Our final Nginx configuration looks like:

    server {
         listen 80;
         listen 443 ssl http2;
         server_name mydomain.com www.mydomain.com;
         ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
         ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
         ssl_prefer_server_ciphers On;
         ssl_certificate /etc/letsencrypt/live/mydomain.com/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/mydomain.com/privkey.pem;
         ssl_session_cache shared:SSL:128m;
         add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
         add_header X-Frame-Options "SAMEORIGIN" always;
         add_header X-Content-Type-Options "nosniff" always;
         add_header X-Xss-Protection "1";
         add_header Content-Security-Policy "default-src 'self'";
         ssl_stapling on;
         ssl_stapling_verify on;
         resolver 8.8.8.8;
         root /var/www/demo;
         index index.html;

         location '/.well-known/acme-challenge' {
          default_type "text/plain";
            root        /var/www/demo;
          }

         location / {
                  if ($scheme = http) {
                    return 301 https://$server_name$request_uri;
                  }
         }
    }

And can be downloaded directly from [here](https://raw.githubusercontent.com/llambiel/letsecureme/master/etc/nginx/conf.d/default.conf).

Let's reload Nginx one more time to apply our new headers:

    nginx -t && sudo nginx -s reload

And scan again our site using [securityheaders.io](https://securityheaders.io/):

_N.B ensure to test using HTTPS._

![alt text](static/images/securityheaders2.png "securityheaders.io final check")

"A" grade, much better! Some of you may have noticied that we didn't enable HPKP (HTTP Public Key Pinning), which would have allowed us to get the A+ grade. In fact we skipped that header as it could really screw your website if the feature is not well understood and carefully planned. This header will be covered in an upcoming detailed blog post.

## Conclusion (To be improved)

Let's Encrypt can be easily deployed and maintained on top of Nginx. Specific SSL and browser headers hardening must be deployed in order to ensure a modern and secure web deployment.

There are many reasons for deploying SSL on your website. Security is, naturally, the most important and obvious one. However, it's also a trust building marker for parts of your audience. To top it all off, Google takes SSL implementation into account in the search results. There are no drawbacks to having an active certificate on your website. With a free certificate from Let's Encrypt and the directions in this blog post there is absolutely no reason to hesitate. Try it now!

---
date: "2016-03-10T10:15:15+01:00"
draft: true
title: "Let's Encrypt & Nginx"
subtitle: "State of the art secure web deployment"
slug: "secure-web-deployment-with-lets-encrypt-and-nginx"
html_title: "Let's Encrypt & Nginx - state of the art secure web deployment"
description: "An overview of a secure web deployment with Let's Encrypt and Nginx. How to set up a valid HTTPS connection, harden it and get top security ratings."
intro: |
    &nbsp;
    
    Not long ago SSL encryption was still considered a nice-to-have feature, and major services secured only log-in pages of theirs applications.

    Things have changed, and for the best: encryption is now considered a must-have, and enforced by most players. Search giant Google even takes SSL implementation into account in search results ranking.

    Despite the larger reach of SSL, setting-up your own secured web service is still considered daunting, time consuming, and error-prone.

    A recent player in the field, [Let's encrypt](https://letsencrypt.org) promises to make SSL certificates more widely available and
    to radically simplify the workflow of maintaining a website's security.

    Combined with the powerful Nginx web server, and with some additional hardening tips, you can use it to achieve top notch security grades, rating A+ on the popular [Qualys SSL](https://www.ssllabs.com/ssltest/) and [securityheaders.io](https://securityheaders.io) analysers.

    In this article, we walk through the steps needed to achieve this.
---

## What you will do
Here are the steps you will go through:

* Spawn a cloud instance which will host our demo website.
* Do some basic hardening of our server and set up Nginx.
* Install a brand new [Let's encrypt](https://letsencrypt.org) certificate and set up its automatic renewal
* Harden the Nginx configuration
* Harden the Security Headers
* Get that shiny A+ security rating you are looking for

This tutorial will use [Exoscale](https://www.exoscale.ch) as cloud provider since they offer integrated firewall and DNS management. On top of that Exoscale has a strong focus on data safety / privacy and security. Of course you can follow along using any other cloud or traditional hosting service.

## Let's Encrypt overview

[Let's Encrypt](https://letsencrypt.org) is a new open source certificate authority (CA) providing free and automated SSL/TLS certificates. Their root certificate is well trusted by most [browsers](https://community.letsencrypt.org/t/which-browsers-and-operating-systems-support-lets-encrypt/4394), and they are actively trying to reduce the painful workflow of creation - validation - signing - installation - renewal of certificates. 

A word of warning before moving on, there are still a few caveats to take into account when considering [Let's encrypt](https://letsencrypt.org):

* It's still in **beta** phase.
* It requires root privileges.
* The client does not yet "officially" support Nginx (but it works flawlessly).
* It installs dependencies automatically (like [Augeas](http://augeas.net/), [gcc](https://gcc.gnu.org/), [Python](https://www.python.org/)).
* Throttling is enforced so you cannot request more than 5 certificates per week for a given domain.
* Certificate is valid for 90 days.

It's possible to get a certificate using other [alternate lightweight and less intrusive clients](https://community.letsencrypt.org/t/list-of-client-implementations/2103) however this tutorial won't cover them.

The official documentation can be found [here](http://letsencrypt.readthedocs.org/en/latest/intro.html), and of course is worth reading.

## Infrastructure setup

Let's begin by spawning a new cloud instance. First of all you'll need a public SSH key at hand. If you don't have your own key, or want a quick setup, Exoscale lets you generate one on the fly before starting your machine. Go under the SSH Keys menu and create your key. [They have a guideline](https://community.exoscale.ch/documentation/compute/ssh-keypairs/) if this stuff is new for you. This tutorial will assume you know what an SSH key is and how to use it.

On the [Exoscale portal](https://portal.exoscale.ch) (or the cloud provider of your choice), start a Linux Ubuntu 14.04. For this demo a micro instance (512mb RAM, 1 Vcpu & 10GB disk) will be more than enough. Choose your SSH key on creation and verify that the "default" Security Group is checked (more on that later).

Within a few seconds our instance is available and ready for use. You can now note down its IP address in order to proceed with the DNS setup.

![Our instance detailed view](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/instance1.png)

Exoscale is providing DNS zone hosting, so you don't need to leave the interface. Just go under DNS and create a new zone ("letsecure.me" in this example, you'll need to use your own domain here).

![DNS zone creation](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/dns1.png)

Now you may add a "A" record with the value of the IP address of our freshly spawned instance, as well as a "catch all" (wildcard) CNAME record:

![DNS record creation](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/dns2.png)

You're done with DNS records. If you are following the tutorial on Exoscale don't forget to update the nameservers of your domain with the ones here below.
You should be able to do so within your domain registrar administration console.

* `ns1.exoscale.com`
* `ns1.exoscale.ch`
* `ns1.exoscale.net`
* `ns1.exoscale.io`

## Basic security hardening of your server

You are now ready to work on our cloud instance, but before beginning to play with certificates and web services, we're going to apply a few elementary security best practices:

On the firewall side you need to allow only the required traffic and deny any other transit. Specifically we'll need to add the rules below:

* 22 (SSH)
* 80 (HTTP)
* 443 (HTTPS)
* ICMP ping (not mandatory but convenient)

On Exoscale firewalls are managed through the interface with what is called *Security Groups*. By default all incoming traffic is denied and all outgoing traffic is allowed. In the detail of your machine you should see it has been registered in the "default" Security Group. You need to modify the "default" group with the mentioned rules. On other cloud providers you may have a similar system or you may have to install your own firewall software. A good and simple choice on Ubuntu would be [UFW](https://help.ubuntu.com/community/UFW).

![Firewall rules](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/firewall1.png)

Another recommended step to harden your machine is to administer it via SSH and keypairs authentication only. Most cloud providers give you this option nowadays. You should already have your key deployed on Exoscale if you've followed along, but if you didn't or if your cloud provider doesn't offer you a similar workflow, it's time to upload your key. This tutorial won't go into details about that, and assumes you are familiar with this.

You can now login via SSH using the _ubuntu_ user.

    ssh ubuntu@yourdomain.here

Now, if you're using SSH key authentication, **and only if so**, you may disable SSH password authentication:

    sudo sed -i 's|PasswordAuthentication yes|PasswordAuthentication no|g' /etc/ssh/sshd_config
    sudo service ssh restart

If you're using [UFW](https://help.ubuntu.com/community/UFW), add the rules below:

    sudo ufw allow out 22/tcp
    sudo ufw allow out 80/tcp
    sudo ufw allow out 443/tc

The next thing to do is to apply all the software updates and patches and reboot the instance:

    sudo apt-get update && sudo apt-get dist-upgrade -y && sudo reboot

This will ensure all software is up to date, including recent bug fixes and security patches. On top of that wouldn't it be nice if the system could keep-up with the latest patches? You can do so by enabling the automatic security updates:

    sudo dpkg-reconfigure --priority=low unattended-upgrades

In this way, whenever an important security update is released the system will update itself keeping everything secure.

It's good practice to install [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) in order to prevent brute force SSH attacks (specifically if you're using password authentication):

    sudo apt-get install -y fail2ban

## Basic Nginx Setup

Now that everything is secured you may take care of Nginx. We're not going to install the package from the Ubuntu repository as we will require features (like HTTP/2) that can only be found in the latest "mainline" release branch. You can add the Nginx official repository using:f

    curl http://nginx.org/keys/nginx_signing.key | sudo apt-key add -
    echo "deb http://nginx.org/packages/mainline/ubuntu/ trusty nginx" | sudo tee --append /etc/apt/sources.list.d/nginx_org_packages_mainline_ubuntu.list
    sudo apt-get update && sudo apt-get install -y nginx

Create the target folder from where our website will be served:

    sudo mkdir /var/www/
    # download our demo website
    wget https://github.com/llambiel/letsecureme/raw/master/demo.tar.gz
    sudo tar zxf demo.tar.gz -C /var/www
    sudo chown -R root:www-data /var/www/

Remove the default Nginx configuration and start with a fresh blank file:

    sudo mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.orig
    sudo touch /etc/nginx/conf.d/default.conf

[Let's Encrypt](https://letsencrypt.org) client will need to create some temporary files required to authenticate the domain for which we're requesting the certificate. To allow this you need to adjust the Nginx configuration block in `/etc/nginx/conf.d/default.conf` with the following:

    server {
        listen 80;
        server_name default_server;
        root /var/www/demo;
        location /.well-known/acme-challenge {
            default_type "text/plain";
        }
    }

Reload Nginx to apply our configuration change and we're done with Nginx for the time being.

    sudo nginx -t && sudo nginx -s reload

## Let's Encrypt setup, SSL certificates and Nginx HTTPS config

Go for Let's Encrypt. As per [the official documentation](https://letsencrypt.readthedocs.org/en/latest/intro.html#installation), you need to clone its [GIT](https://github.com/letsencrypt/letsencrypt) repository and launch `letsencrypt-auto`:

    sudo apt-get install -y git
    sudo git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt
    /opt/letsencrypt/letsencrypt-auto

Note that as said in the beginning, the setup script will install all the required dependencies automatically. Although convenient, this implies that you lose some control of what is installed on your machine.

You can now request a certificate for your domain. You'll get prompted to provide your email address for the expiring notifications and accept the Terms:

    export DOMAINS="yourdomain.here,www.yourdomain.here"
    export DIR=/var/www/demo
    /opt/letsencrypt/letsencrypt-auto certonly --server https://acme-v01.api.letsencrypt.org/directory -a webroot --webroot-path=$DIR -d $DOMAINS

You need of course to use your own domain name in the `DOMAINS` list.

Our cert should now be issued and installed!

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

Let's Encrypt keeps configuration and certificates organized under `/etc/letsencrypt`. The [Let's Encrypt documentation](https://letsencrypt.readthedocs.org/en/latest/using.html#where-are-my-certificates) will give you detailed information about the structure and the content of the directory.

To use your new certificate you need to instruct Nginx to serve it and bind the port 443 on ssl. You may use the following minimal configuration block in `/etc/nginx/conf.d/default.conf`.

    server {
        listen 443 ssl;
        server_name yourdomain.here www.yourdomain.here;
        root /var/www/demo;
        ssl_certificate /etc/letsencrypt/live/yourdomain.here/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/yourdomain.here/privkey.pem;
    }

Let's reload Nginx one more time:

    sudo nginx -t &&  sudo nginx -s reload

Now point your web browser to https://yourdomain.here  
Your website homepage should now be served over HTTPS. \o/ 

As previously mentioned, [Let's encrypt](https://letsencrypt.org) delivers certificates that are valid 90 days only. To ensure that our certificate gets renewed automatically we're going to use a small script and a crontab.

Save the following in a file called renewCerts.sh.

    #!/bin/sh
    # This script renews all the Let's Encrypt certificates with a validity < 30 days

    if ! /opt/letsencrypt/letsencrypt-auto renew > /var/log/letsencrypt/renew.log 2>&1 ; then
        echo Automated renewal failed:
        cat /var/log/letsencrypt/renew.log
        exit 1
    fi
    nginx -t && nginx -s reload

A daily cron will trigger our script. To set up the crontab open it...

    sudo crontab -e

...and add a line with the `@daily` macro:

    @daily /path/to/renewCerts.sh

Save and quit your editor. Don't forget to set the script executable using:

    chmod +x /path/to/renewCerts.sh

Congratulations! You can now serve your content through HTTPS with a valid certificate which renews itself automatically.

Still, if you check your grade using the default SSL/TLS configuration on [SSL analyser](https://www.ssllabs.com/ssltest/), the result is not really good.
Let's pimp a bit our Nginx config to improve our rating!

## Nginx SSL/TLS hardening 

Remove the actual config in `/etc/nginx/conf.d/default.conf` and replace it by the block below. Remember to modify the block with your own domain name:

    server {
        listen 80;
        listen 443 ssl http2;
        server_name yourdomain.here www.yourdomain.here;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
        ssl_prefer_server_ciphers On;
        ssl_certificate /etc/letsencrypt/live/yourdomain.here/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/yourdomain.here/privkey.pem;
        ssl_session_cache shared:SSL:128m;
        add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
        ssl_stapling on;
        ssl_stapling_verify on;
        # Your favorite resolver may be used instead of the Google one below
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



When done, reload Nginx:

    sudo nginx -t && sudo nginx -s reload

### Detail of the SSL/TLS configuration

Let's review some important config items that we've just added:

    listen 443 ssl http2;

With this directive, you tell Nginx to listen over SSL and also support the connection over the new [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) standard, if the client browser support / request it. Please note that HTTP/2 is SSL/TLS only!

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

Disable old and weak SSLv2/SSLv3 protocols and allow only the TLS ones.

    ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
    ssl_prefer_server_ciphers On;
    
This is the cipher list you tell Nginx to support. This list is in my opinion one of the most well balanced between security and support by older web browsers. Nginx will prefer those ciphers over the ones requested by the client.

    ssl_stapling on;
    ssl_stapling_verify on;

Enable OCSP stapling, which is well described in details [here](https://www.maxcdn.com/one/visual-glossary/ocsp-stapling/).

    add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";

This adds an HTTP header instructing the client browser to force a HTTPS connection to your domain and to all of its subdomains for 1 year.  
**Warning!** Be careful here before applying it in production, you must ensure first that **all your subdomains (if any) are being secured as well**. Your subdomains will be forced over https as well, and if not properly configured, will become unreachable.

Let's re-test again our setup with [Qualys SSL](https://www.ssllabs.com/ssltest/):

![Qualys SSL final check](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/qualys2.png)

Hey, this looks much better now ! Our setup is now secured using an optimal SSL/TLS configuration, our first objective is achieved.

## Security headers hardening

Now, what about the content / behavior of our website? [Scott Helme](https://securityheaders.io/about/) created a great HTTP response headers [analyser](https://securityheaders.io/) to assess the security grade of our content based on headers.

If you test your current setup (ensure to test using HTTPS!) the result is, well... not so good:

![securityheaders.io first check](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/securityheaders1.png)

Again let's tune a bit our Nginx configuration by adding a few HTTP headers:

    add_header X-Content-Type-Options "nosniff" always;

The [X-Content-Type-Options](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options) header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type.

    add_header X-Frame-Options "SAMEORIGIN" always;

The [X-Frame-Options](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options) header tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking.

    add_header X-Xss-Protection "1";

The [X-Xss-Protection](https://scotthelme.co.uk/hardening-your-http-response-headers/#x-xss-protection) header sets the configuration for the cross-site scripting filter built into most browsers.

    add_header Content-Security-Policy "default-src 'self'";

The Content-Security-Policy header defines approved sources of content that the browser may load. It can be an effective countermeasure to Cross Site Scripting (XSS) attacks. **WARNING!** This header must be carefully planned before deploying it on production website as it could easily break stuff and prevent a website to load it's content! Fortunately there is a "report mode" available. In the mode, the browser will only report any issue in the debug console but not actually block the content. This is really helpful to ensure a smooth deployment of this header:

![report mode](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/reportmode.png)

The configuration of this policy is well described [here](https://scotthelme.co.uk/content-security-policy-an-introduction/)

The report mode can be enabled using:

    Content-Security-Policy-Report-Only instead of Content-Security-Policy

## Final secured Nginx configuration

Your final Nginx configuration should look like this:

    server {
         listen 80;
         listen 443 ssl http2;
         server_name yourdomain.here www.yourdomain.here;
         ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
         ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
         ssl_prefer_server_ciphers On;
         ssl_certificate /etc/letsencrypt/live/yourdomain.here/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/yourdomain.here/privkey.pem;
         ssl_session_cache shared:SSL:128m;
         add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
         add_header X-Frame-Options "SAMEORIGIN" always;
         add_header X-Content-Type-Options "nosniff" always;
         add_header X-Xss-Protection "1";
         add_header Content-Security-Policy "default-src 'self'; script-src 'self' *.google-analytics.com";
         ssl_stapling on;
         ssl_stapling_verify on;
         # Your favorite resolver may be used instead of the Google one below
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



Let's reload Nginx one more time to apply our new headers:

    sudo nginx -t && sudo nginx -s reload

And scan again our site using [securityheaders.io](https://securityheaders.io/)(again, remember to scan it with the https:// prefix):

![securityheaders.io final check](/img/2016-03-10-secure-web-deployment-with-lets-encrypt-and-nginx/securityheaders2.png)

You should have got an "A" grade, which sounds much better!

Some of you may have noticed that we didn't enable HPKP (HTTP Public Key Pinning), which would have allowed us to get the A+ grade. In fact that header could really screw your website if the feature is not well understood and carefully planned. This subject may be developed in this page in the future, stay tuned.

## Conclusion

There are many reasons for deploying SSL/TLS on your website. Security is, naturally, the most important and obvious one. However, it's also a trust building marker for parts of your audience. There are no drawbacks to having an active certificate on your website. With a free certificate from Let's Encrypt and following the steps described in this tutorial, there is absolutely no reason to hesitate.

Let's Encrypt can be easily deployed and maintained on top of Nginx, and with Specific SSL/TLS and browser headers hardening you can achieve a modern and secure web deployment.

Source files of this project can be downloaded directly from [GitHub](https://
raw.githubusercontent.com/llambiel/letsecureme/).

This project will be expanded and kept updated to follow the future releases and improvements of Let's Encrypt and Nginx, not to mention the future best practices of a state of the art secure web deployment.

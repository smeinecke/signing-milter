# signing-milter in systemd
signing-milter enables you to s/mime sign an ordinary mail while passing a MTA. It is written in C and tested with the postfix MTA. It should work with any MTA implementing the milter protocol.

This repository replaces the `daemontools` service manager used in the original release by the Debian standard `systemd` service.

## Installation
Install the required dependencies (if not already done):

```bash
apt-get install libcdb1 libmilter1.0.1 tinycdb
```

Download the current release (no Debian repository at the time of writing) for your Debian version and install the .deb file:

```bash
wget https://github.com/smeinecke/signing-milter/releases/latest/download/signing-milter_20220416-bullseye_amd64.deb
dpkg -i signing-milter_20220416-bullseye_amd64.deb
```

## Basic postfix configuration
In default configuration the postfix daemon is chrooted to the spool folder located in `/var/spool/postfix/`. To use the socket feature of signing-milter the socket + permissions has to be configured in the `/etc/default/signing-milter` file:
```ini
#DISABLE_HOURLY_STATISTIK_LOGGING='yes'
#DISABLE_DAILY_STATISTIK_LOGGING='yes'
OPTIONS="-s unix:/var/spool/postfix/signing-milter/signing-milter.sock -c postfix"
```

Also create the folder within the postfix spool folder with the correct permissions:
```bash
mkdir -m o-rwx /var/spool/postfix/signing-milter
chown signing-milter:postfix /var/spool/postfix/signing-milter
```

The socket has to be configured in postfix in main.cf as new milter:
```ini
smtpd_milters = unix:signing-milter/signing-milter.sock
```

And reload/restart the services:
```bash
systemctl restart signing-milter
systemctl reload postfix
```

## Configure certificates
All certificates are configured in the `/etc/signing-milter/sigingtable` file.

Just add the email address + path of the pem file and use
```bash
make
```
to update the `cdb` database and trigger reloading signing-milter.

The certificates have to be readable by the `signing-milter` user.

## Intermediate certificates
Since version 20120731 signing-milter also supports intermediate certificates.

Just name your certificate with the suffix `-cert+key.pem` and put the intermediate + root certificate in a file suffixed by `-chain.pem` in the same folder.

## Contributing
The project is based on [signing-milter.org](https://signing-milter.org/) by Andreas Schulze.
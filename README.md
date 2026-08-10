# signing-milter in systemd
signing-milter enables you to s/mime sign an ordinary mail while passing a MTA. It is written in C and tested with the postfix MTA. It should work with any MTA implementing the milter protocol.

This repository replaces the `daemontools` service manager used in the original release by the Debian standard `systemd` service.

## Debian/Ubuntu Repository

### Currently supported debian/ubuntu versions:
 * buster
 * bullseye
 * bookworm
 * trixie
 * focal
 * jammy
 * noble
 * resolute

### How to add this repository:

#### Automatically via script
```bash
wget -O- https://smeinecke.github.io/signing-milter/scripts/add-repository.sh | bash
apt-get install signing-milter
```

#### Manually

##### Legacy one-line source
For releases still using the traditional one-line `sources.list` format (Debian buster/bullseye/bookworm, Ubuntu focal/jammy):

```bash
apt-get install wget lsb-release ca-certificates
wget -O /usr/share/keyrings/smeinecke.github.io-signing-milter.key https://smeinecke.github.io/signing-milter/public.key
echo "deb [signed-by=/usr/share/keyrings/smeinecke.github.io-signing-milter.key] https://smeinecke.github.io/signing-milter/repo $(lsb_release -sc) main" > /etc/apt/sources.list.d/signing-milter.list
apt-get update && apt-get install signing-milter
```

##### DEB822 source
For releases using the new DEB822 `.sources` format (Debian trixie, Ubuntu noble/resolute):

```bash
apt-get install wget lsb-release ca-certificates
wget -O /usr/share/keyrings/smeinecke.github.io-signing-milter.key https://smeinecke.github.io/signing-milter/public.key
cat > /etc/apt/sources.list.d/signing-milter.sources <<EOF
Types: deb
URIs: https://smeinecke.github.io/signing-milter/repo
Suites: $(lsb_release -sc)
Components: main
Signed-By: /usr/share/keyrings/smeinecke.github.io-signing-milter.key
EOF
apt-get update && apt-get install signing-milter
```

## Build from source

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

Optional dmalloc support:

```bash
cmake -DENABLE_DMALLOC=ON -DCMAKE_BUILD_TYPE=Release ..
make
```

To build a Debian package:

```bash
dpkg-buildpackage -us -uc -b
```

## Optional Redis certificate backend

If `signing-milter` is built with `WITH_REDIS=ON` (the default), it can fetch
S/MIME certificates and private keys from a Redis server instead of, or in
addition to, the local CDB `signingtable`.

The Redis key for an address is built from the configured prefix and the
lowercased address (e.g. `signing-milter:sender@example.com`). The hash must
contain the following fields:

* `pem` (required): a PEM blob containing both the signer certificate and the
  corresponding private key.
* `chain` (optional): a PEM blob with the intermediate/root certificate chain.

Example Redis `HMSET`:

```bash
redis-cli HMSET signing-milter:sender@example.com \
    pem "$(cat /path/to/sender-cert+key.pem)" \
    chain "$(cat /path/to/sender-chain.pem)"
```

To enable the Redis certificate backend, add `-r`, optionally `-P` and `-W`, to
`/etc/default/signing-milter`:

```ini
OPTIONS="-s unix:/var/spool/postfix/signing-milter/signing-milter.sock -c postfix -r rediss://127.0.0.1:6380/0?verify=peer -P signing-milter: -W /etc/signing-milter/passphrase"
```

Redis TLS (`rediss://`) is supported when built with `WITH_REDIS_SSL=ON`.
It uses TLS 1.2 or newer and never falls back to older protocol versions.
`verify=peer` (the default and only supported mode) validates the server
certificate chain and hostname/IP.  The expected identity defaults to the URI
host; use `verify_name=hostname` to override it.  Use `sni=hostname` to set the
TLS SNI extension without changing the verified identity.  Plaintext TCP
(`redis://`) and `verify=none` are rejected.  IPv6 hosts must be bracketed:
`rediss://[::1]:6380/0`.  The `cert=` file may include the leaf client
certificate plus any required intermediates.

The passphrase file is used for encrypted private keys loaded from Redis. When
Redis is enabled, the milter queries Redis first; on a miss it falls back to the
local CDB `signingtable`.

Redis Unix-socket URIs (`-r unix:/run/redis/redis.sock`) are validated before
the connection is used: the socket path must be absolute, the parent directory
must not be world- or group-writable (unless protected by a sticky bit), and the
socket peer credentials (SO_PEERCRED) must match the socket owner.  Place the
socket in a directory owned by the Redis user and not writable by untrusted
users.

## Auth-signing-table

To allow an authenticated SMTP/SASL user to sign, an `auth-signing-table` can
be configured with `-a` (local CDB) or `-R` (Redis).  If either option is set,
that table is authoritative.

If neither `-a` nor `-R` is configured, `signing-milter` falls back to
certificate-based authorization.  The selected signer must have a certificate
whose subject contains **exactly one Common Name (CN)**, and that CN must match
the authenticated SASL identity from `{auth_authen}` exactly (case-sensitive,
opaque string comparison).  This fallback is intended for deployments where the
organization's PKI deliberately encodes the SMTP/SASL account identity in the
certificate CN.

The authenticated identity is read from the libmilter macro `{auth_authen}`.
This macro contains the SASL login name, which is treated as an **opaque
string** and matched case-sensitively.  It is *not* an email address and is not
lowercased or stripped of angle brackets.

The selected signing identity (envelope `MAIL FROM` or the `X-Signer` header
when `-f` is enabled) is an email address and is normalized (lowercase,
angle brackets removed) before the authorization check.  Note that the entire
address is lowercased, including the local-part; this matches common MTA
behaviour but means a case-sensitive local-part such as `Alice` and `alice`
is treated as a single signer identity.  If your deployment distinguishes
local-parts by case, store them as separate lowercased signer identities.

### Certificate-CN fallback (no `-a` / `-R`)

Without `-a` or `-R`, the milter uses the selected signer's certificate as the
authorization source.  The certificate subject must contain exactly one CN, and
that CN is compared byte-for-byte with `{auth_authen}`.

```text
{auth_authen} = alice
signer certificate subject CN = alice
=> allowed

{auth_authen} = bob
signer certificate subject CN = alice
=> denied

{auth_authen} = alice
signer certificate subject CN = Alice
=> denied (case-sensitive)
```

Authorization is denied if the certificate is missing, contains no CN, or
contains multiple CN attributes.  This fallback only works when the
organization's PKI deliberately places the SMTP/SASL account identity in the
certificate CN.  Explicit auth tables (`-a`/`-R`) are recommended when the CN
cannot be kept in a strict one-to-one relationship with SMTP authentication
identities.

### Local CDB auth-signing-table

Create a text file with one or more records per authenticated identity.  The
key (left-hand side) is the exact authenticated identity and the value
(right-hand side) is one or more signing identities, separated by commas or
whitespace.  The signer values are normalized before comparison, so
`<Sender@EXAMPLE.COM>` and `sender@example.com` are equivalent.

```text
alice                sender@example.com, sales@example.com
bob@example.org      other@example.com
case@example.org     <Sender@EXAMPLE.COM>, sales@example.com
```

Compile the table with `cdb` and reference it with `-a`:

```bash
cdb -c -m /etc/signing-milter/authsigningtable.cdb /etc/signing-milter/authsigningtable
OPTIONS="... -a /etc/signing-milter/authsigningtable.cdb"
```

### Redis auth-signing-table

If Redis support is compiled in, the auth-signing-table can also be stored in
Redis.  The key is `<prefix>auth:<identity>` and contains a Redis set of
permitted signing identities.  The default prefix is `signing-milter:`.

Because the lookup uses `SISMEMBER`, set members must be stored in the
**canonical (normalized) signer form**: lowercased and without angle brackets.

```bash
redis-cli SADD signing-milter:auth:alice                sender@example.com
redis-cli SADD signing-milter:auth:alice                sales@example.com
redis-cli SADD signing-milter:auth:bob@example.org      other@example.com
redis-cli SADD signing-milter:auth:case@example.org     sender@example.com sales@example.com
```

Enable it with `-R` together with the Redis URI and optional prefix:

```ini
OPTIONS="... -R -r rediss://127.0.0.1:6380/0?verify=peer -P signing-milter:"
```

### Postfix configuration for authenticated submission

To make sure the milter sees the authenticated identity, attach it directly to
the submission service used by authenticated clients.  Do **not** put the
signer in the global `smtpd_milters` setting and then let port 25/internet
clients reach it; that recreates the signing oracle this feature is intended
to guard against.

```ini
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_milters=unix:/var/spool/postfix/signing-milter/signing-milter.sock
```

For additional safety, use Postfix `smtpd_sender_login_maps` and
`reject_authenticated_sender_login_mismatch` so an authenticated client cannot
use an envelope sender it does not own.  With both mechanisms in place, an
attacker who authenticates as `alice` cannot force the milter to sign as
`ceo@example.com` either through `MAIL FROM` or through an `X-Signer` header.

## Build from source with or without Redis

By default CMake searches for `libhiredis` and enables Redis support:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

To build without Redis support (no `libhiredis` dependency):

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DWITH_REDIS=OFF
cmake --build build -j"$(nproc)"
```

## Run the Docker integration tests

The full test suite including the Redis end-to-end test can be run with Docker
Compose:

```bash
docker compose -f tests/docker-compose.yml up --build --abort-on-container-exit
```

## Basic postfix configuration
In default configuration the postfix daemon is chrooted to the spool folder located in `/var/spool/postfix/`. To use the socket feature of signing-milter the socket + permissions has to be configured in the `/etc/default/signing-milter` file:
```ini
#DISABLE_HOURLY_STATISTICS_LOGGING='yes'
#DISABLE_DAILY_STATISTICS_LOGGING='yes'
OPTIONS="-s unix:/var/spool/postfix/signing-milter/signing-milter.sock -c postfix"
```

Also create the folder within the postfix spool folder with the correct
permissions.  When the milter starts as root the socket directory must be
root-owned, otherwise a prior (compromised) daemon instance could race the
socket creation:
```bash
install -d -o root -g postfix -m 0750 \
    /var/spool/postfix/signing-milter
```

The socket has to be configured in postfix as a milter on the appropriate
listener.  For an internal, trusted submission-only listener that may be:

```ini
smtpd_milters = unix:signing-milter/signing-milter.sock
```

> **Warning:** Do not attach `signing-milter` globally to an Internet-facing
> MX listening on port 25 unless you have another trusted mechanism that
> guarantees the sender is authorized for the signing identity.  When an
> `auth-signing-table` is configured (recommended for authenticated-sender signing;
> otherwise certificate-CN fallback is used),
> use the milter only on the authenticated `submission` service, and combine it
> with Postfix `smtpd_sender_login_maps` /
> `reject_authenticated_sender_login_mismatch`.

And reload/restart the services:
```bash
systemctl restart signing-milter
systemctl reload postfix
```

## Configure certificates
All certificates are configured in the `/etc/signing-milter/signingtable` file.

Just add the email address + path of the pem file and use
```bash
cd /etc/signing-milter && make
```
to update the `cdb` database and trigger reloading signing-milter.

The certificates have to be readable by the `signing-milter` user.

## Intermediate certificates
Since version 20120731 signing-milter also supports intermediate certificates.

Just name your certificate with the suffix `-cert+key.pem` and put the intermediate + root certificate in a file suffixed by `-chain.pem` in the same folder.

## Contributing

The project is based on [signing-milter.org](https://signing-milter.org/) by Andreas Schulze.

Thanks to [Rouven Spreckels](https://github.com/n3vu0r) for the statistics
logging fix in [PR #9](https://github.com/smeinecke/signing-milter/pull/9).

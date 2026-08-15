#!/bin/sh
# To add this repository please do:

if [ "$(whoami)" != "root" ]; then
    SUDO=sudo
fi

KEYRING=/usr/share/keyrings/smeinecke.github.io-signing-milter.key
REPO_URL=https://smeinecke.github.io/signing-milter/repo

${SUDO} apt-get update
${SUDO} apt-get -y install lsb-release ca-certificates wget
${SUDO} wget -O "${KEYRING}" https://smeinecke.github.io/signing-milter/public.key

codename=$(lsb_release -sc)
vendor=$(lsb_release -si | tr '[:upper:]' '[:lower:]')

if [ -f "/etc/apt/sources.list.d/${vendor}.sources" ]; then
    ${SUDO} rm -f /etc/apt/sources.list.d/signing-milter.list
    cat <<EOF | ${SUDO} tee /etc/apt/sources.list.d/signing-milter.sources >/dev/null
Types: deb
URIs: ${REPO_URL}
Suites: ${codename}
Components: main
Signed-By: ${KEYRING}
EOF
else
    ${SUDO} rm -f /etc/apt/sources.list.d/signing-milter.sources
    echo "deb [signed-by=${KEYRING}] ${REPO_URL} ${codename} main" | ${SUDO} tee /etc/apt/sources.list.d/signing-milter.list >/dev/null
fi

${SUDO} apt-get update

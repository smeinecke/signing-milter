#!/bin/sh
# To add this repository please do:

if [ "$(whoami)" != "root" ]; then
    SUDO=sudo
fi

${SUDO} apt-get update
${SUDO} apt-get -y install lsb-release ca-certificates wget
${SUDO} wget -O /usr/share/keyrings/smeinecke.github.io-signing-milter.key https://smeinecke.github.io/signing-milter/public.key
echo "deb [signed-by=/usr/share/keyrings/smeinecke.github.io-signing-milter.key] https://smeinecke.github.io/signing-milter/repo $(lsb_release -sc) main" | ${SUDO} tee /etc/apt/sources.list.d/signing-milter.list
${SUDO} apt-get update

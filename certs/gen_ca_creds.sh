#!/bin/bash

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` <ca-common-name>"
  exit
fi

echo "Generating TLS credentials for CA \(${1}\)"
echo "Please make sure you generate enough entropy!"
certtool --generate-privkey >ca-key.pem
echo "cn = ${1}" > ca.tmpl
echo "ca" >> ca.tmpl
echo "cert_signing_key" >> ca.tmpl
certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl >ca-cert.pem
rm ca.tmpl

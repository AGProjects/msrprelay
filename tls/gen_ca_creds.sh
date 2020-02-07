#!/bin/bash

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` <ca-common-name>"
  exit
fi

echo "Generating TLS credentials for CA \"${1}\""
echo "Please make sure you generate enough entropy!"
certtool --generate-privkey >ca.key
echo "cn = ${1}" > ca.tmpl
echo "ca" >> ca.tmpl
echo "cert_signing_key" >> ca.tmpl
echo "expiration_days = 10000" >>ca.tmpl
certtool --generate-self-signed --load-privkey ca.key --template ca.tmpl --outfile ca.crt
rm ca.tmpl


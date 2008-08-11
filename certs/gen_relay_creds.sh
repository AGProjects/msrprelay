#!/bin/bash

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` <msrprelay-hostname>"
  exit
fi

if [ ! -f "ca-key.pem" ] || [ ! -f "ca-cert.pem" ]
then
  echo "Please generate the CA key/certificate pair first."
  exit
fi

echo Generating TLS credentials for MSRP relay \"$1\"
echo Please make sure you generate enough entropy!
certtool --generate-privkey >${1}-key.pem
echo "cn = ${1}" >> ${1}.tmpl
echo "dns_name = ${1}" >> ${1}.tmpl
echo "tls_www_server" >> ${1}.tmpl
echo "tls_www_client" >> ${1}.tmpl
echo "encryption_key" >> ${1}.tmpl
echo "signing_key" >> ${1}.tmpl
echo "expiration_days = 10000" >>${1}.tmpl
certtool --generate-certificate --load-privkey ${1}-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template ${1}.tmpl --outfile ${1}-cert.pem
rm ${1}.tmpl

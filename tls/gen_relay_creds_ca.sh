#!/bin/bash

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` <msrprelay-hostname>"
  exit
fi

if [ ! -f "ca.key" ] || [ ! -f "ca.crt" ]
then
  echo "Please generate the CA key/certificate pair first."
  exit
fi

echo Generating TLS credentials for MSRP relay \"$1\"
echo Please make sure you generate enough entropy!
certtool --generate-privkey >msrprelay.key
echo "cn = ${1}" >> ${1}.tmpl
echo "dns_name = ${1}" >> ${1}.tmpl
echo "tls_www_server" >> ${1}.tmpl
echo "tls_www_client" >> ${1}.tmpl
echo "encryption_key" >> ${1}.tmpl
echo "signing_key" >> ${1}.tmpl
echo "expiration_days = 10000" >>${1}.tmpl
certtool --generate-certificate --load-privkey msrprelay.key --load-ca-certificate ca.crt --load-ca-privkey ca.key --template ${1}.tmpl --outfile msrprelay.crt
rm ${1}.tmpl


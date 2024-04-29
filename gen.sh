#!/bin/bash

# Script configuration
PASSWORD="Keystore1!"  # Replace with a strong password

# Generate CA key and certificate
openssl req -new -x509 -keyout ca-key.pem -out ca-cert.pem \
  -days 3650 \
  -passout pass:$PASSWORD

# Generate server key and CSR
openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr \
  -passout pass:$PASSWORD

# Sign server certificate with CA
openssl x509 -req -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -in server.csr -out server-cert.pem -days 3650 -sha384 -passin pass:$PASSWORD

# Convert server key to PKCS12 for easy import
openssl pkcs12 -export -inkey server-key.pem -in server-cert.pem \
  -out server.p12 -passout pass:$PASSWORD -passin pass:$PASSWORD

# Generate client key and CSR
openssl req -newkey rsa:2048 -keyout client-key.pem -out client.csr \
  -passout pass:$PASSWORD

# Sign client certificate with CA
openssl x509 -req -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -in client.csr -out client-cert.pem -days 3650 -sha384 -passin pass:$PASSWORD

# Convert client key to PKCS12 for easy import
openssl pkcs12 -export -inkey client-key.pem -in client-cert.pem \
  -out client.p12 -passout pass:$PASSWORD -passin pass:$PASSWORD

# Create server keystore (JKS) 
keytool -importkeystore -deststorepass $PASSWORD -destkeypass $PASSWORD \
  -destkeystore server-keystore.jks -srckeystore server.p12 -srcstoretype pkcs12 \
  -srcstorepass $PASSWORD 
  

# Create server truststore (JKS)
keytool -importcert -alias CARoot -file ca-cert.pem \
  -keystore server-truststore.jks -noprompt -storepass $PASSWORD 

# Create client truststore (JKS)
keytool -importcert -alias CARoot -file ca-cert.pem \
  -keystore client-truststore.jks -noprompt -storepass $PASSWORD 

# Create a server certificate for manual import (optional)
openssl x509 -outform pem -in server-cert.pem > server-certificate.crt 

echo "** Script completed. Remember to replace 'changeme' with a strong password!**"
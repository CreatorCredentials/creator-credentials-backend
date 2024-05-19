#!/bin/bash
# Create a self-signed x509 certificate

# See the EDIT_ME sections and update them accordingly

# start EDIT_ME
## define the organisatio name for which the key is generated
SUBJECT=$2
##  Set the validity period (e.g. 1 year) and date from which the x509 certificate is valid
VALIDITY_DAYS=$3
VALID_FROM=20231201000000Z
## end EDIT_ME


## Directory in which the certificates are created 
dir=$1
rootDir=${dir}/${SUBJECT}

# Path to the x509 configuration file
CONFIG_FILE=${rootDir}/config.cnf

## Create basic dir structure
mkdir -p ${rootDir}/{certs,crl,newcerts,private,csr}
echo 1000 > ${rootDir}/serial
echo 0100 > ${rootDir}/crlnumber
touch ${rootDir}/index.txt

# Generate root CA keys:
## Key output file
secretKey=${rootDir}/private/key.secret.pem
cert=${rootDir}/certs/cert.pem

## EDIT_ME: You can create RSA or EC key; Uncomment the corresponding line
### EC P-256 (default)
# openssl ecparam -out ${secretKey} -name prime256v1 -genkey 
### RSA key:
# openssl genrsa -out ${secretKey} 4096
### EC P-384
# openssl ecparam -out ${secretKey} -name secp384r1 -genkey 
### EC P-521
# openssl ecparam -out ${secretKey} -name secp521r1 -genkey 
### EC ED25519
# openssl genpkey -algorithm ED25519 -out ${secretKey}
### X25519
# openssl genpkey -algorithm x25519 -out ${secretKey}
### X448
# openssl genpkey -algorithm x448 -out ${secretKey}
### ED448
# openssl genpkey -algorithm ed448 -out ${secretKey}

## Set key permissions
# chmod 400 ${secretKey}

## Create a Root CA cert
# openssl ca -config ${CONFIG_FILE} -days ${VALIDITY_DAYS} -out ${cert} -extensions v3_ca -startdate ${VALID_FROM}
## Set cert permissions
#chmod 444 ${cert}

openssl ecparam -name prime256v1 -out ec_params.pem

openssl req -new -newkey ec:ec_params.pem -nodes -keyout ${secretKey} -config ${CONFIG_FILE} -x509 -sha256 -out ${cert} -days ${VALIDITY_DAYS} -extensions v3_c2pa

# openssl req -new -newkey ec:ec_params.pem -nodes -x509 -sha256 -keyout private3.ke

openssl x509 -in ${cert} -text

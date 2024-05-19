const subject = 'alice';
const directory = `self-signed/${subject}`;

const countryName = 'SI';
const stateOrProvinceName = 'SI';
const localityName = 'Wonderland';
const organizationName = 'Alice inc.';

const organizationalUnitName = 'RND';
const commonName = 'Root CA - Alice';

const crlDistributionPoints = 'URI:https://alice.com/crl.crl';

const issuerURI1 = 'did:web:alice.com';
const issuerURI2 = 'https://alice.com';

const subjectURI1 = 'did:web:alice.com';
const subjectURI2 = 'https://alice.com';

export const defaultCnfCertificateConfig = getCnfCertificateConfig({
  directory,
  subject,
  countryName,
  stateOrProvinceName,
  localityName,
  organizationName,
  organizationalUnitName,
  commonName,
  crlDistributionPoints,
  issuerURI1,
  issuerURI2,
  subjectURI1,
  subjectURI2,
});

export type CertificateConfigOptions = {
  directory: string;
  subject: string;
  countryName: string;
  stateOrProvinceName: string;
  localityName: string;
  organizationName: string;
  organizationalUnitName: string;
  commonName: string;
  crlDistributionPoints: string;
  issuerURI1: string;
  issuerURI2: string;
  subjectURI1: string;
  subjectURI2: string;
};
export function getCnfCertificateConfig({
  directory,
  subject,
  countryName,
  stateOrProvinceName,
  localityName,
  organizationName,
  organizationalUnitName,
  commonName,
  crlDistributionPoints,
  issuerURI1,
  issuerURI2,
  subjectURI1,
  subjectURI2,
}: CertificateConfigOptions) {
  const cnfCertificateConfigTemplate = `
  # self-signed.cnf
# Profile: C2PA
# Example of a self-signed x509 certificate configuration

[ req ]
## EDIT_ME: define the root directory
dir                 = ${directory}/${subject} 
## EDIT_ME: path to the secret key
default_keyfile     = $dir/private/key.secret.pem

default_ca          = CA_root
keyform             = PEM
req_extensions      = v3_c2pa
x509_extensions     = v3_c2pa
prompt              = no
distinguished_name  = dn_creator

[ dn_creator ]
# EDIT_ME: REQUIRED. Define the subject name
commonName            = ${commonName}
# EDIT_ME: REQUIRED. Define the 2 letter country code of the subject
countryName           = ${countryName}
# EDIT_ME: REQUIRED. Define the 2 letter state code of the subject
stateOrProvinceName   = ${stateOrProvinceName}
# EDIT_ME: REQUIRED. Define the locality (e.g., city)
localityName          = ${localityName}
# EDIT_ME: REQUIRED. Define the official organization name
organizationName      = DID:key:${organizationName}
# EDIT_ME: OPTIONAL. define the org. unit in which the subject works.
organizationalUnitName= ${organizationalUnitName}

[ issuer_alt_names ]
URI.1                = ${issuerURI1}
URI.2                = ${issuerURI2}

[ subject_alt_names ]
URI.1                = ${subjectURI1}
URI.2                = ${subjectURI2}

[ CA_root ]               
dir                 = ${directory}/${subject}                    # Output directory
certs               = $dir/certs                           # Certificates directory
crl_dir             = $dir/crl                             # CRL directory
new_certs_dir       = $dir/newcerts                        # New certificates directory
database            = $dir/index.txt                       # Certificate index file
serial              = $dir/serial                          # Serial number file
private_key         = $dir/private/key.secret.pem          # Intermediate CA private key
certificate         = $dir/certs/cert.pem                  # Intermediate CA certificate
default_md          = sha256                               # Default message digest

[ v3_c2pa ]                                           # Root CA certificate extensions
subjectKeyIdentifier   = hash                         # Subject key identifier
authorityKeyIdentifier = keyid:always,issuer          # Authority key identifier
basicConstraints       = critical, @basic_constraints
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, emailProtection
issuerAltName          = @issuer_alt_names
subjectAltName         = @subject_alt_names
crlDistributionPoints  = ${crlDistributionPoints}


[ basic_constraints ]
CA      = false
pathlen = 0`;

  return cnfCertificateConfigTemplate;
}

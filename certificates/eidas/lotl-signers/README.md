# EU LOTL signer trust anchors

This directory contains the certificates that are authorized to XAdES-sign the
European Commission's List of Trusted Lists (LOTL) at
`https://ec.europa.eu/tools/lotl/eu-lotl.xml`.

These PEMs are the **bootstrap trust anchor** of the eIDAS pipeline used by the
cert-challenge feature. The chain of trust is:

1. The XAdES signature on the LOTL XML is verified against one of the certs in
   this directory. Any other signer is rejected.
2. The validated LOTL declares, for each EU member state, a Trusted List URL
   and the certificate(s) that are allowed to sign that country's TL.
3. Each country TL is XAdES-validated against its announced signer certs, then
   parsed for QSeal / QSig CA anchors.
4. User-submitted X.509 certificates are validated against the resulting
   anchor set.

## How to refresh

The EU rotates the LOTL signer roughly every few years and announces the new
certificate via the Official Journal of the EU. When that happens:

```bash
pnpm ts-node scripts/refresh-lotl-bootstrap.ts
```

The script downloads the current LOTL, extracts every cert in
`<ds:Signature>/<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`, prints their
SHA-256 fingerprints + Subject DNs, and writes new PEM files to this
directory. Verify the printed fingerprints against the OJ before deploying.

## Files

Each PEM file is named `eu-lotl-signer-YYYY-MM.pem` where `YYYY-MM` is the
month the cert was added to the bootstrap set.

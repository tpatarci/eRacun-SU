# Certificate Storage (`secrets/certificates/`)

This directory is reserved for **SOPS-encrypted** certificate bundles. Do **not**
place plaintext `.p12`, `.pem`, `.crt`, or `.key` files under version control.

## Expected Files

| File | Purpose |
| --- | --- |
| `fina-demo-client.p12.enc` | Demo certificate for `cistest.apis-it.hr` SOAP/AS4 connectivity |
| `fina-demo-client.key.enc` | Extracted PEM key from demo certificate |
| `fina-demo-client.crt.enc` | Extracted PEM certificate chain |
| `fina-root-ca.pem.enc` | Trusted CA bundle for demo/prod environments |
| `fina-prod-client.p12.enc` | Production certificate (5–10 day issuance) |

> **Note:** The `.enc` suffix indicates the file is encrypted with SOPS. The
> decrypted material must be written to `/run/eracun/certificates/` during
> deployment via the `decrypt-secrets.sh` helper referenced in
> `deployment/systemd/README.md`.

## Usage Workflow

1. Obtain the raw certificate from FINA (demo or production).
2. Convert PKCS#12 → PEM components when needed:
   ```bash
   openssl pkcs12 -in fina-demo-client.p12 -out fina-demo-client.key -nodes -nocerts
   openssl pkcs12 -in fina-demo-client.p12 -out fina-demo-client.crt -nokeys
   ```
3. Encrypt each artifact with SOPS + age:
   ```bash
   sops --encrypt fina-demo-client.p12 > secrets/certificates/fina-demo-client.p12.enc
   shred -u fina-demo-client.p12
   ```
4. Repeat for `.key`, `.crt`, and CA bundles. Never commit the plaintext.
5. Update the service configuration to point at the decrypted paths (defaults
   expect `/etc/eracun/secrets/certificates/`).

## Missing Artifacts

The actual certificates are **not** available inside this repository. Obtaining
and encrypting them requires NIAS-authenticated access to `cms.fina.hr` and the
production age key material, both of which are unavailable in this sandbox.
Ops/compliance must perform the encryption workflow before deployments.

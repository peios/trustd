# Certificate-policy fixtures

`leaf.pem` and `expired-ca.pem` are synthetic, self-signed P-256
certificates for the tests of the kinds of failure libtrust reports. No
private keys are stored.

- `leaf.pem`, `CN=Peios test leaf`, has a critical BasicConstraints
  extension with `cA` false, so the store refuses it as no certificate
  authority. It is valid until 2126.
- `expired-ca.pem`, `CN=Peios test expired CA`, is a certificate authority
  that was valid from 2000-01-01 to 2001-01-01, so the store refuses it as
  expired.

Generated with OpenSSL 3.5's `req -x509` and an ephemeral EC key, with
SHA-256 signatures. These are test data only; never install them as trust
anchors.

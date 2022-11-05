# yuberify

This is a library that uses YubiKey to create Verifiable Presentation.

## Prerequisite
Download the Yubico PIV Tool [here](https://developers.yubico.com/yubico-piv-tool/Releases/).

Set a random chuid, import a key and import a certificate from a PKCS12 file, into slot 9c:

```
$ yubico-piv-tool -s9c -icert.pfx -KPKCS12 -aset-chuid \
  -aimport-key -aimport-cert
```
If you have not already created a key pair, you can do so by following these steps.
```
e.g.)
$ openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
$ openssl ec -in private-key.pem -pubout -out public-key.pem
$ openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
$ openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx
```

```
$ yubico-piv-tool -a verify-pin --sign -s 9c -H SHA256 -A ECCP256 -i data.txt -o data.sig
Enter PIN:
Successfully verified PIN.
Signature successful!
$ openssl dgst -sha256 -verify public-key.pem -signature data.sig data.txt
Verified OK
```

## Usage

```
$ git clone https://github.com/KinyouBenkyokai/yuberify.git 
```

## References
- [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/)
- [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/)
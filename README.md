# ykvp

ykpv is a library(and includes command line tool) for signing verifiable presentation using yubikey from verifiable credential.
and also has a function to issue a verifiable credential as an issuer.

## Documentation 

You can find out more details from the [godocs](https://pkg.go.dev/github.com/kinyoubenkyokai/ykvp).

## Prerequisite

This library depends on [piv-go](https://github.com/go-piv/piv-go). Check [here](https://github.com/go-piv/piv-go#installation) for details.

## Sample

There is a [sample](https://github.com/KinyouBenkyokai/ykvp/tree/main/sample) and [CLI](https://github.com/KinyouBenkyokai/ykvp/tree/main/cmd/ykvpcli) that utilize libraries on this repository.

## References
- [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html)
- [A Go YubiKey PIV implementation](https://github.com/go-piv/piv-go)
# ykvpcli 

ykvpcli is a command line tool for creating verifiable presentation using yubikey from verifiable credential.

## Installation

```bash
$ go install github.com/kinyoubenkyokai/ykvp/cmd/ykvpcli@v0.0.3
```

## Usage

```
$ ykvpcli \ 
    -c '{"context":["https://www.w3.org/2018/credentials/v1"],"type":["GraduationCredential","VerifiableCredential"],"issuanceDate":"2022-11-06T20:40:25.560358+09:00","credentialSubject":{"id":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFd2VabHl4emtaL0xFQUdPNE9NMnJCYVliRnplRAorNnYrQmFzTW1hZWx2ZDNZNTZGR2RBQjY4UmZtYk05UVl4NUkvUlg4Qk1KZndSWDVhdFBuUFNXdlp3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","claim":{"age":24,"universityName":"Oxford","degree":"Bachelor of Science"}},"proof":{"type":"ecdsasecp256k1signature2019","created":"2022-11-06T20:40:25.560671+09:00","creator":{"Curve":{"P":1.1579208921035625e+77,"N":1.1579208921035625e+77,"B":4.105836372515214e+76,"Gx":4.8439561293906455e+76,"Gy":3.6134250956749796e+76,"BitSize":256,"Name":"P-256"},"X":6.72469815416677e+76,"Y":3.327515407817215e+76},"signature":"MEQCIBTOi0ZLu1E58GEhAalQl2FhRuc1EP6kPRj0aUBYV6kGAiBh9kRilqKLj1dk+xeTFmf2PXxjYgR0HEDeHI6xdvk0WA=="}}'
```

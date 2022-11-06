# ykvp

Verifiable Presentation の Proof の生成に YubiKey を利用可能とする Go 言語のライブラリおよび CLI の実装です。
Web5 を構成する仕様の一つである W3C Verifiable Credentials Data Model 仕様において、Holder が Verifiable Credential (VC) を Verifier に共有する際、Holder は VC に対して署名を行い、Verifiable Presentation (VP) というデータ構造にします。
このとき、本ライブラリを利用して Digital Wallet を実装することで Holder が署名に YubiKey を利用できるようになり、鍵管理を YubiKey に任せることが可能になります。
また、本ライブラリが利用する YubiKey の鍵のスロットは、FIDO 仕様で利用されるものとは異なる領域になっており、FIDO 仕様との共存が可能になっています。
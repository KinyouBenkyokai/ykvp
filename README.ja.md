# ykvp

Verifiable Presentation の Proof の生成に YubiKey を利用可能とする Go 言語のライブラリおよび CLI の実装です。
Web5 を構成する仕様の一つである [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) 仕様において、Holder が Verifiable Credential (VC) を Verifier に共有する際、Holder は VC に対して署名を行い、Verifiable Presentation (VP) というデータ構造にします。
このとき、本ライブラリを利用して Digital Wallet を実装することで Holder が署名に YubiKey を利用できるようになり、鍵管理を YubiKey に任せることが可能になります。
また、本ライブラリが利用する YubiKey の鍵のスロットは、FIDO 仕様で利用されるものとは異なる領域になっており、FIDO 仕様との共存が可能になっています。

## ドキュメント

ライブラリの詳細は [godocs](https://pkg.go.dev/github.com/kinyoubenkyokai/ykvp) をご覧ください。

## 前提条件 

このライブラリは [piv-go](https://github.com/go-piv/piv-go) に依存しています。OS ごとの必要な設定は[ここ](https://github.com/go-piv/piv-go#installation)からご確認ください。

## サンプル

このリポジトリ上にライブラリを利用した[サンプル](https://github.com/KinyouBenkyokai/ykvp/tree/main/sample)および [CLI](https://github.com/KinyouBenkyokai/ykvp/tree/main/cmd/ykvpcli) があります。

## 参照
- [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html)
- [A Go YubiKey PIV implementation](https://github.com/go-piv/piv-go)
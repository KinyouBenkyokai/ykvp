package yubico

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"github.com/go-piv/piv-go/piv"
	"github.com/golang/mock/gomock"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestYubiKeySignECDSA(t *testing.T) {
	yk, err := NewYubikey()
	defer yk.Close()
	pubKey, err := yk.GenerateKey()
	out, err := yk.SignByYubikey(pubKey, []byte("hello"), 123456)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		t.Fatalf("unmarshaling signature: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		t.Errorf("signature didn't match")
	}
}

func TestYubikey_GenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		getYk   func(t *testing.T) pivYubikey
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			name: "generate key",
			getYk: func(t *testing.T) pivYubikey {
				myk := NewMockpivYubikey(gomock.NewController(t))
				myk.EXPECT().
					GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, piv.Key{
						Algorithm:   piv.AlgorithmEC256,
						PINPolicy:   piv.PINPolicyAlways,
						TouchPolicy: piv.TouchPolicyAlways,
					}).
					Return(ecdsa.PublicKey{}, nil)
				return myk
			},
			want:    ecdsa.PublicKey{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Yubikey{
				yk: tt.getYk(t),
			}
			got, err := s.GenerateKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubikey_SignByYubikey(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P384(), strings.NewReader(strings.Repeat("random test data", 100)))
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	type args struct {
		pub  crypto.PublicKey
		text []byte
		pin  int32
	}
	tests := []struct {
		name    string
		getYk   func(t *testing.T) pivYubikey
		args    args
		wantErr bool
	}{
		{
			name: "",
			args: args{
				pub:  pk.Public(),
				text: []byte("hello"),
				pin:  123456,
			},
			getYk: func(t *testing.T) pivYubikey {
				myk := NewMockpivYubikey(gomock.NewController(t))
				myk.EXPECT().
					PrivateKey(piv.SlotSignature, pk.Public(), piv.KeyAuth{
						PIN:       "123456",
						PINPolicy: piv.PINPolicyAlways,
					}).
					Return(pk, nil)
				return myk
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Yubikey{
				yk: tt.getYk(t),
			}
			_, err := s.SignByYubikey(tt.args.pub, tt.args.text, tt.args.pin)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignByYubikey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

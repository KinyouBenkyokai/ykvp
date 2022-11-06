package entity

import (
	"reflect"
	"testing"
	"time"
)

func TestUnmarshalCredential(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *CredentialToSign
		wantErr bool
	}{
		{
			name: "",
			args: args{
				b: []byte("{\"context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"GraduationCredential\",\"VerifiableCredential\"],\"issuanceDate\":\"2021-05-30T15:00:00Z\",\"credentialSubject\":{\"id\":\"\",\"claim\":{\"age\":22,\"universityName\":\"University of Tokyo\",\"degree\":\"Bachelor\"}}}"),
			},
			want: &CredentialToSign{
				Context:          []string{"https://www.w3.org/2018/credentials/v1"},
				TypeOfCredential: []string{"GraduationCredential", "VerifiableCredential"},
				IssuanceDate:     time.Date(2021, 5, 30, 15, 0, 0, 0, time.UTC),
				CredentialSubject: CredentialSubject{
					ID: []byte(""),

					Claim: Claim{
						Age:            22,
						UniversityName: "University of Tokyo",
						Degree:         "Bachelor",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalCredential(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalCredential() got = %v, want %v", got, tt.want)
			}
		})
	}
}

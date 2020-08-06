package agilekeychain

import (
	"reflect"
	"testing"
)

func TestNewAgileKeychain(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *AgileKeychain
		wantErr bool
	}{
		{ // this fixture shamelessly copied from https://github.com/alsemyonov/one_password
			name:    "Create new agilekeychain from fixture",
			args:    args{path: "testdata/agilekeychain/example/1Password.agilekeychain"},
			want:    &AgileKeychain{baseDir: "testdata/agilekeychain/example/1Password.agilekeychain"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAgileKeychain(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAgileKeychain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAgileKeychain() = %v, want %v", got, tt.want)
			}
		})
	}
}

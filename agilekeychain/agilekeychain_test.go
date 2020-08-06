package agilekeychain

import (
	"os"
	"path"
	"reflect"
	"testing"
)

func TestNewAgileKeychain_Errors(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *AgileKeychain
		wantErr bool
	}{
		{
			name:    "Test nonexistent directory",
			args:    args{path: "/nonexist4329489erjgar"},
			want:    nil,
			wantErr: true,
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

func TestNewAgileKeychain_Example1(t *testing.T) {
	// this fixture shamelessly copied from https://github.com/alsemyonov/one_password
	fixturePath := "../testdata/agilekeychain/example1/1Password.agilekeychain"

	keychain1, err := NewAgileKeychain(fixturePath)
	if err != nil {
		t.Errorf("Error creating agilekeychain from fixture with relative path: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("os.Getwd failed: %v", err)
	}

	absPath := path.Join(cwd, fixturePath)
	keychain2, err := NewAgileKeychain(absPath)
	if err != nil {
		t.Errorf("Error creating agilekeychain from fixture with absolute path: %v", err)
	}

	if !reflect.DeepEqual(keychain1, keychain2) {
		t.Errorf("Keychains from absolute and relative paths differ! relative: %v absolute: %v", keychain1, keychain2)
	}

}

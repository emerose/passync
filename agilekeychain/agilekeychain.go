package agilekeychain

import (
	"fmt"
	"os"
	"path"
)

// AgileKeychain represents a 1password AgileKeychain
// see design discussion here: https://support.1password.com/cs/agile-keychain-design/
type AgileKeychain struct {
	baseDir string
}

// NewAgileKeychain creates a new AgileKeychain object, given a path
// returns an error if path doesn't exist or is not a directory
func NewAgileKeychain(keychainPath string) (*AgileKeychain, error) {
	if !path.IsAbs(keychainPath) {
		dir, err := os.Getwd()

		if err != nil {
			return nil, fmt.Errorf("Couldn't get current dir: %v", err)
		}

		keychainPath = path.Join(dir, keychainPath)
	}

	ret := &AgileKeychain{
		baseDir: keychainPath,
	}

	fileinfo, err := os.Stat(keychainPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("Non-existent AgileKeychain path %s: %v", keychainPath, err)
	}

	if !fileinfo.IsDir() {
		return nil, fmt.Errorf("AgileKeychain path %s not a directory", keychainPath)
	}

	return ret, nil
}

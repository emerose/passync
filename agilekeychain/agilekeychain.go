package agilekeychain

// AgileKeychain represents a 1password AgileKeychain
// see design discussion here: https://support.1password.com/cs/agile-keychain-design/
type AgileKeychain struct {
	baseDir string
}

// NewAgileKeychain creates a new AgileKeychain object, given a path
// NOTE: this does no validation on the path or its contents!
func NewAgileKeychain(path string) (*AgileKeychain, error) {
	ret := &AgileKeychain{
		baseDir: path,
	}

	return ret, nil
}

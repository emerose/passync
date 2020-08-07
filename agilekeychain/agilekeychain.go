package agilekeychain

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
)

// AgileKeychain represents a 1password AgileKeychain
// see design discussion here: https://support.1password.com/cs/agile-keychain-design/
type AgileKeychain struct {
	baseDir  string
	contents keychainContents
}

// keychainContents is an array of keychainContentsEntrys
type keychainContents []keychainContentsEntry

// each entry is an array, but I'm not actually sure what the elements are
type keychainContentsEntry struct {
	id        string
	entryType string
	title     string
	site      string
	date      int
	unknown1  string
	unknown2  int
	unknown3  string
}

// NewAgileKeychain creates a new AgileKeychain object, given a path
// returns an error if path doesn't exist or is not a directory
func NewAgileKeychain(keychainPath string) (*AgileKeychain, error) {
	if !path.IsAbs(keychainPath) {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
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

	err = ret.loadContents()
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// load contents.js into contents
func (k *AgileKeychain) loadContents() error {
	contentsPath := path.Join(k.baseDir, "data", "default", "contents.js")
	f, err := os.Open(contentsPath)
	if err != nil {
		return err
	}

	type rawKeychainEntry []interface{}
	type rawKeychainContents []rawKeychainEntry
	var rawContents rawKeychainContents

	err = json.NewDecoder(f).Decode(&rawContents)
	if err != nil {
		return err
	}

	cookedContents := make([]keychainContentsEntry, len(rawContents))

	for ix, entry := range rawContents {
		var e keychainContentsEntry
		var ok bool
		var tmp float64

		allOk := true

		e.id, ok = entry[0].(string)
		allOk = allOk && ok

		e.entryType, ok = entry[1].(string)
		allOk = allOk && ok

		e.title, ok = entry[2].(string)
		allOk = allOk && ok

		e.site, ok = entry[3].(string)
		allOk = allOk && ok

		tmp, ok = entry[4].(float64)
		e.date = int(tmp)
		allOk = allOk && ok

		e.unknown1, ok = entry[5].(string)
		allOk = allOk && ok

		tmp, ok = entry[6].(float64)
		e.unknown2 = int(tmp)
		allOk = allOk && ok

		e.unknown3, ok = entry[7].(string)
		allOk = allOk && ok

		if !allOk {
			return fmt.Errorf("Failed to parse keychain contents entry: %#v", entry)
		}
		cookedContents[ix] = e
	}

	k.contents = cookedContents
	return err
}

// Length of the keychain
func (k *AgileKeychain) Length() int {
	return len(k.contents)
}

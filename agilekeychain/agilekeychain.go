package agilekeychain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/pbkdf2"
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

	err = ret.loadEncryptionKeys("1Password")
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
	return nil
}

func (k *AgileKeychain) loadEncryptionKeys(passphrase string) error {
	type rawEncryptionKey struct {
		Data       string
		Validation string
		Level      string
		Identifier string
		Iterations int
	}

	type rawEncryptionKeys struct {
		SL3  string
		SL5  string
		List []rawEncryptionKey
	}

	contentsPath := path.Join(k.baseDir, "data", "default", "encryptionKeys.js")
	f, err := os.Open(contentsPath)
	if err != nil {
		return err
	}

	var raw rawEncryptionKeys

	err = json.NewDecoder(f).Decode(&raw)
	if err != nil {
		return err
	}

	log.Printf("Found %d keys", len(raw.List))

	for _, rawKey := range raw.List {
		// these strings end in "\u0000" which makes for some invalid base64
		rawKey.Data = stripTrailingNull(rawKey.Data)
		rawKey.Validation = stripTrailingNull(rawKey.Validation)

		data, err := base64.StdEncoding.DecodeString(rawKey.Data)
		if err != nil {
			return err
		}
		validation, err := base64.StdEncoding.DecodeString(rawKey.Validation)
		if err != nil {
			return err
		}

		keyBytes, err := decryptKey(data, rawKey.Iterations, passphrase)
		err = validateKey(keyBytes, validation)
		if err != nil {
			return fmt.Errorf("Failed to validate key %s: %v", rawKey.Identifier, err)
		}
		log.Printf("Found and validated key %s", rawKey.Identifier)
	}
	return nil
}

func stripTrailingNull(str string) string {
	if strings.HasSuffix(str, "\u0000") {
		return str[0 : len(str)-len("\u0000")]
	}
	return str
}

func decryptKey(dataBytes []byte, iterations int, passphrase string) ([]byte, error) {
	salt, blob, err := extractSalt(dataBytes)
	if err != nil {
		return nil, err
	}

	derivedKey := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha1.New)

	// the key-encrypting key
	kek := derivedKey[0:16]
	// and associated IV
	iv := derivedKey[16:32]

	key, err := cbcDecrypt(blob, kek, iv)

	return key, nil
}

func validateKey(keyBytes []byte, validationBytes []byte) error {
	salt, blob, err := extractSalt(validationBytes)
	if err != nil {
		return err
	}

	kek, iv := deriveOpensslKey(keyBytes, salt)

	validationResult, err := cbcDecrypt(blob, kek, iv)
	if err != nil {
		return err
	}

	if !bytes.Equal(keyBytes, validationResult) {
		return errors.New("key validation failed")
	}
	return nil
}

func cbcDecrypt(blob []byte, key []byte, iv []byte) (output []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	if err != nil {
		return nil, err
	}

	ret := make([]byte, len(blob))
	decrypter.CryptBlocks(ret, blob)

	ret, err = unpad(ret, decrypter.BlockSize())
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// remove pkcs7 padding
func unpad(data []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("Invalid block size")
	}

	if data == nil || len(data) == 0 {
		return nil, errors.New("Invalid data")
	}

	if len(data)%blocksize != 0 {
		return nil, errors.New("Input is not a multiple of blocksize")
	}

	// in pkcs7, there is always at least one byte of padding, and the character
	// used to fill it is the length of the padding
	lastByte := data[len(data)-1]
	padSize := int(lastByte)
	if padSize == 0 || padSize > len(data) {
		return nil, errors.New("Invalid pad size")
	}

	// check that the padding is actual padding
	padding := data[len(data)-padSize:]
	for _, b := range padding {
		if b != lastByte {
			return nil, errors.New("Invalid padding")
		}
	}

	return data[:len(data)-padSize], nil
}

// OpenSSL has a particular way of storing a salt alongside a blob
func extractSalt(input []byte) (salt []byte, blob []byte, err error) {
	// if the data starts with "Salted__", then the first 8 bytes following that are the salt
	if bytes.Equal(input[0:8], []byte(`Salted__`)) {
		return input[8:16], input[16:], nil
	} else {
		// Some code on the Internet returns a salt of all zeros in this case, but I'm not
		// confident that's the correct behavior.  We throw an error instead; if you're reading
		// this, you might try uncommenting the following line
		//		return []byte{0, 0, 0, 0, 0, 0, 0, 0}, input, nil
		return nil, nil, errors.New("No OpenSSL salt found")
	}
}

// OpenSSL also has a particular/odd key derivation function
func deriveOpensslKey(password []byte, salt []byte) (key []byte, iv []byte) {
	rounds := 2
	data := append(password, salt...)
	md5Hashes := make([][]byte, rounds)
	sum := md5.Sum(data)

	md5Hashes[0] = append([]byte{}, sum[:]...)

	for i := 1; i < rounds; i++ {
		sum = md5.Sum(append(md5Hashes[i-1], data...))
		md5Hashes[i] = append([]byte{}, sum[:]...)
	}

	return md5Hashes[0], md5Hashes[1]
}

// Length of the keychain
func (k *AgileKeychain) Length() int {
	return len(k.contents)
}

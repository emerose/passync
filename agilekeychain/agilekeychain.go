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

	for _, key := range raw.List {
		// these strings end in "\u0000" which makes for some invalid base64
		if strings.HasSuffix(key.Data, "\u0000") {
			key.Data = key.Data[0 : len(key.Data)-len("\u0000")]
		}
		if strings.HasSuffix(key.Validation, "\u0000") {
			key.Validation = key.Validation[0 : len(key.Validation)-len("\u0000")]
		}

		data, err := base64.StdEncoding.DecodeString(key.Data)
		if err != nil {
			return err
		}
		validation, err := base64.StdEncoding.DecodeString(key.Validation)
		if err != nil {
			return err
		}

		_, err = decryptKey(data, validation, key.Iterations, passphrase)
	}
	return nil
}

func decryptKey(dataBytes []byte, validationBytes []byte, iterations int, passphrase string) ([]byte, error) {
	var salt []byte

	// if the data starts with "Salted__", then the first 8 bytes following that are the salt for PBKDF2
	if bytes.Equal(dataBytes[0:8], []byte(`Salted__`)) {
		salt = dataBytes[8:16]
	} else {
		salt = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	}

	// encrypted key bytes
	encryptedKey := dataBytes[16:]

	derivedKey := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha1.New)

	// the key-encrypting key
	kek := derivedKey[0:16]
	// and associated IV
	iv := derivedKey[16:32]

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	if err != nil {
		return nil, err
	}

	key := make([]byte, len(encryptedKey))
	decrypter.CryptBlocks(key, encryptedKey)

	key, err = unpad(key, decrypter.BlockSize())
	if err != nil {
		return nil, err
	}

	// now, validate it

	// if the data starts with "Salted__", then the first 8 bytes following that are the salt for PBKDF2
	if bytes.Equal(validationBytes[0:8], []byte(`Salted__`)) {
		salt = validationBytes[8:16]
	} else {
		salt = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		return nil, fmt.Errorf("unsalted validation data not implemented")
	}

	encryptedBytes := validationBytes[16:]

	kek, iv = deriveKey(key, salt)

	block, err = aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	decrypter = cipher.NewCBCDecrypter(block, iv)
	if err != nil {
		return nil, err
	}

	validationResult := make([]byte, len(encryptedBytes))
	decrypter.CryptBlocks(validationResult, encryptedBytes)

	validationResult, err = unpad(validationResult, decrypter.BlockSize())
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(key, validationResult) {
		return nil, errors.New("failed to validate key")
	}

	return key, nil
}

// unpad is needed because this is how openssl pads aes-128-cbc, so we
// need to unpad as well in order to properly decrypt the data. Note
// that this should conform to PCKS#7.
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

	lastByte := data[len(data)-1]
	padSize := int(lastByte)
	if padSize == 0 || padSize > len(data) {
		return nil, errors.New("Invalid pad size")
	}

	padding := data[len(data)-padSize:]
	for _, b := range padding {
		if b != lastByte {
			return nil, errors.New("Invalid padding")
		}
	}

	return data[:len(data)-padSize], nil
}

func deriveKey(password []byte, salt []byte) (key []byte, iv []byte) {
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

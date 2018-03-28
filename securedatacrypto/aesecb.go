package securedatacrypto

import (
	"crypto/aes"
	"errors"
	"reflect"
)

type aesECBSecureData struct {
	key []byte
}

// AESSize represents the size of AES
type AESSize int

const (
	AES128 AESSize = 128
	AES256 AESSize = 256
)

// ErrInvalidAlgorithm represents invalid encryption algorithm error
var ErrInvalidAlgorithm = errors.New("aesecb: invalid encryption algorithm")

func (sd aesECBSecureData) Encrypt(text string) (string, error) {
	encrypted, err := sd.encrypt([]byte(text))
	return string(encrypted), err
}

func (sd aesECBSecureData) Decrypt(encryptedText string) (string, error) {
	if encryptedText == "" {
		return encryptedText, nil
	}
	decrypted, err := sd.decrypt([]byte(encryptedText))
	return string(decrypted), err
}

// EncryptStruct changes value of instance
func (sd aesECBSecureData) EncryptStruct(instance interface{}) (interface{}, error) {
	instanceType := reflect.TypeOf(instance).Elem()
	for i := 0; i < instanceType.NumField(); i++ {
		currentFieldName := instanceType.Field(i).Name
		currentFieldTag := instanceType.Field(i).Tag
		cryptValue, hasCryptTag := currentFieldTag.Lookup("crypt")
		if hasCryptTag && cryptValue == "true" {
			instanceValue := reflect.ValueOf(instance).Elem()
			field := instanceValue.FieldByName(currentFieldName)
			if field.IsValid() && field.Kind() == reflect.String {
				encryptedFieldValue, err := sd.Encrypt(field.String())
				if err != nil {
					return nil, err
				}
				field.SetString(encryptedFieldValue)
			} else {
				return nil, errors.New("Field must be a string to be encrypted")
			}
		}
	}
	return instance, nil
}

// DecryptStruct changes value of instance
func (sd aesECBSecureData) DecryptStruct(encryptedInstance interface{}) (interface{}, error) {
	instanceType := reflect.TypeOf(encryptedInstance).Elem()
	for i := 0; i < instanceType.NumField(); i++ {
		currentFieldName := instanceType.Field(i).Name
		currentFieldTag := instanceType.Field(i).Tag
		cryptValue, hasCryptTag := currentFieldTag.Lookup("crypt")
		if hasCryptTag && cryptValue == "true" {
			instanceValue := reflect.ValueOf(encryptedInstance).Elem()
			field := instanceValue.FieldByName(currentFieldName)
			if field.IsValid() && field.Kind() == reflect.String {
				decryptedFieldValue, err := sd.Decrypt(field.String())
				if err != nil {
					return nil, err
				}
				field.SetString(decryptedFieldValue)
			} else {
				return nil, errors.New("Field must be a string to be decrypted")
			}
		}
	}
	return encryptedInstance, nil
}

func NewAESECB(size AESSize, key string) Crypto {
	return &aesECBSecureData{key: aesKey(size, []byte(key))}
}

func aesKey(aesKeyLen AESSize, key []byte) []byte {
	keyLen := int(aesKeyLen) / 8

	if len(key) == keyLen {
		return key
	}

	k := make([]byte, keyLen)
	copy(k, key)
	for i := keyLen; i < len(key); {
		for j := 0; j < keyLen && i < len(key); j, i = j+1, i+1 {
			k[j] ^= key[i]
		}
	}
	return k
}

func (sd aesECBSecureData) encrypt(plaintext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(sd.key)
	if err != nil {
		return nil, err
	}

	numberOfBlocks := (len(plaintext) + aes.BlockSize) / aes.BlockSize
	ciphertext := make([]byte, numberOfBlocks*aes.BlockSize)
	srctext := make([]byte, numberOfBlocks*aes.BlockSize)
	copy(srctext, plaintext)
	padLen := byte(len(srctext) - len(plaintext))
	for i := len(plaintext); i < len(srctext); i++ {
		srctext[i] = padLen
	}

	for bs, be := 0, aes.BlockSize; bs < len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		cipher.Encrypt(ciphertext[bs:be], srctext[bs:be])
	}

	return ciphertext, nil
}

func (sd aesECBSecureData) decrypt(ciphertext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(sd.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrInvalidAlgorithm
	}

	decryptedFull := make([]byte, len(ciphertext))

	for bs, be := 0, aes.BlockSize; bs < len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		cipher.Decrypt(decryptedFull[bs:be], ciphertext[bs:be])
	}

	padLen := int(decryptedFull[len(decryptedFull)-1])

	if padLen > len(decryptedFull) {
		return nil, ErrInvalidAlgorithm
	}

	decryptedLen := len(decryptedFull) - padLen
	decripted := make([]byte, decryptedLen)
	copy(decripted, decryptedFull[:decryptedLen])

	return decripted, nil
}

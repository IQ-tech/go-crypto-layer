package datacrypto

import (
	"crypto/aes"
	"errors"
	"reflect"
)

// aesECBSecureData implements Crypto interface using AES ECB to encrypt and decrypt data
type aesECBSecureData struct {
	key []byte
}

// AESSize represents the size of AES
type AESSize int

// AESSize allowed values
const (
	AES128 AESSize = 128
	AES256 AESSize = 256
)

// ErrInvalidAlgorithm represents invalid encryption algorithm error
var ErrInvalidAlgorithm = errors.New("aesecb: invalid encryption algorithm")

// Encrypt encrypts a string
func (sd aesECBSecureData) Encrypt(text string) (string, error) {
	encrypted, err := sd.encrypt([]byte(text))
	return string(encrypted), err
}

// Decrypt decrypts a string
func (sd aesECBSecureData) Decrypt(encryptedText string) (string, error) {
	if encryptedText == "" {
		return encryptedText, nil
	}
	decrypted, err := sd.decrypt([]byte(encryptedText))
	return string(decrypted), err
}

// EncryptStruct crawls all anottated struct properties and encrypts them in place
func (sd aesECBSecureData) EncryptStruct(instance interface{}) (retVal interface{}, err error) {
	instanceType := reflect.TypeOf(instance)
	if instanceType.Kind() != reflect.Ptr {
		return nil, errors.New("must receive a pointer, but received " + instanceType.Kind().String())
	}

	instanceType = instanceType.Elem()
	if instanceType.Kind() != reflect.Struct {
		return nil, errors.New("must receive a pointer to a struct, but received " + instanceType.Kind().String())
	}

	instanceValue := reflect.ValueOf(instance).Elem()

	for i := 0; i < instanceType.NumField(); i++ {
		currentFieldTag := instanceType.Field(i).Tag
		cryptValue, hasCryptTag := currentFieldTag.Lookup("crypt")
		field := instanceValue.Field(i)

		if field.IsValid() && field.CanSet() {
			switch field.Kind() {
			case reflect.String:
				if hasCryptTag && cryptValue == "true" {
					encryptedFieldValue, err := sd.Encrypt(field.String())
					if err != nil {
						return nil, err
					}
					field.SetString(encryptedFieldValue)
				}

			case reflect.Ptr:
				if !field.IsNil() && field.Elem().IsValid() {
					switch field.Elem().Kind() {
					case reflect.String:
						if hasCryptTag && cryptValue == "true" {
							encryptedFieldValue, err := sd.Encrypt(field.Elem().String())
							if err != nil {
								return nil, err
							}
							field.Elem().SetString(encryptedFieldValue)
						}
					case reflect.Struct:
						_, err := sd.EncryptStruct(field.Interface())
						if err != nil {
							return nil, err
						}
					}
				}
			case reflect.Struct:
				_, err = sd.EncryptStruct(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			default:
				if hasCryptTag && cryptValue == "true" {
					return nil, errors.New("Field must be a string or a pointer to a string to be decrypted")
				}
			}
		}
	}

	return instance, nil
}

// DecryptStruct crawls all anottated struct properties and deecrypts them in place
func (sd aesECBSecureData) DecryptStruct(encryptedInstance interface{}) (interface{}, error) {
	instanceType := reflect.TypeOf(encryptedInstance)
	if instanceType.Kind() != reflect.Ptr {
		return nil, errors.New("must receive a pointer, but received " + instanceType.Kind().String())
	}

	instanceType = instanceType.Elem()
	if instanceType.Kind() != reflect.Struct {
		return nil, errors.New("must receive a pointer to a struct, but received " + instanceType.Kind().String())
	}

	instanceValue := reflect.ValueOf(encryptedInstance).Elem()

	for i := 0; i < instanceType.NumField(); i++ {
		currentFieldTag := instanceType.Field(i).Tag
		cryptValue, hasCryptTag := currentFieldTag.Lookup("crypt")
		field := instanceValue.Field(i)

		if field.IsValid() && field.CanSet() {
			switch field.Kind() {
			case reflect.String:
				if hasCryptTag && cryptValue == "true" {
					decryptedFieldValue, err := sd.Decrypt(field.String())
					if err != nil {
						return nil, err
					}
					field.SetString(decryptedFieldValue)
				}

			case reflect.Ptr:
				if !field.IsNil() && field.Elem().IsValid() {
					switch field.Elem().Kind() {
					case reflect.String:
						if hasCryptTag && cryptValue == "true" {
							decryptedFieldValue, err := sd.Decrypt(field.Elem().String())
							if err != nil {
								return nil, err
							}
							field.Elem().SetString(decryptedFieldValue)
						}
					case reflect.Struct:
						_, err := sd.DecryptStruct(field.Interface())
						if err != nil {
							return nil, err
						}
					}
				}
			case reflect.Struct:
				_, err := sd.DecryptStruct(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			default:
				if hasCryptTag && cryptValue == "true" {
					return nil, errors.New("Field must be a string or a pointer to a string to be decrypted")
				}
			}
		}
	}

	return encryptedInstance, nil
}

// NewAESECB returns a new Crypto using AES ECB
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

// encrypt encrypts a byte array
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

// decrypt decrypts a byte array
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

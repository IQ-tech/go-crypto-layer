package datacrypto

// Crypto interface to implement new cryptography methods
type Crypto interface {
	Encrypt(text string) (string, error)
	Decrypt(encryptedText string) (string, error)
	EncryptStruct(instance interface{}) (interface{}, error)
	DecryptStruct(encryptedInstance interface{}) (interface{}, error)
}

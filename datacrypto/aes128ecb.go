package datacrypto

// NewAES128ECB instantiate a new Crypto using AES 128 with ECB
func NewAES128ECB(key string) Crypto {
	return NewAESECB(AES128, key)
}

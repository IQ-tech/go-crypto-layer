package securedatacrypto

func NewAES128ECB(key string) Crypto {
	return NewAESECB(AES128, key)
}

package secret

import (
	"secret-cli/encrypt"
)

func Memory(encodingKey string) Vault {
	return Vault{
		encodingKey: encodingKey,
		keyValues:   make(map[string]string),
	}
}

type Vault struct {
	encodingKey string
	keyValues   map[string]string
}

func (v *Vault) Get(key string) (string, error) {
	hex, ok := v.keyValues[key]
	if !ok {
		return hex, nil
	}
	ret, err := encrypt.Decrypt(v.encodingKey, hex)
	if err != nil {
		return "", err
	}

	return ret, nil
}

func (v *Vault) Set(key, value string) error {
	encryptedValue, err := encrypt.Encrypt(v.encodingKey, value)
	if err != nil {
		panic(err)
	}
	v.keyValues[key] = encryptedValue
	return nil
}
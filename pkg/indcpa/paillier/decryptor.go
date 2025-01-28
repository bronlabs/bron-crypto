package paillier

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type Decryptor struct {
	sk *SecretKey
}

func NewDecryptor(secretKey *SecretKey) (*Decryptor, error) {
	if err := secretKey.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid secret key")
	}

	return &Decryptor{sk: secretKey}, nil
}

func (d *Decryptor) Decrypt(cipherText *CipherText) (*PlainText, error) {
	return d.sk.Decrypt(cipherText)
}

func (d *Decryptor) Validate() error {
	if d == nil {
		return errs.NewIsNil("decryptor")
	}
	if err := d.sk.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid sk")
	}

	return nil
}

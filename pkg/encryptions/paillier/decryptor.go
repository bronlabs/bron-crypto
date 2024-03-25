package paillier

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
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
	if err := cipherText.Validate(&d.sk.PublicKey); err != nil {
		return nil, errs.WrapFailed(err, "invalid cipher text")
	}

	mu := d.sk.GetPrecomputed().Mu
	nMod := d.sk.PublicKey.GetPrecomputed().NModulus
	nnMod := d.sk.PublicKey.GetPrecomputed().NNModulus
	crt := &d.sk.GetPrecomputed().CrtNN

	cToLambda := expCrt(crt, cipherText.C, d.sk.Phi, nnMod)
	l := d.sk.L(cToLambda)
	m := new(saferith.Nat).ModMul(l, mu, nMod)

	return m, nil
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

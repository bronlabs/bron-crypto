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

	mu, err := d.sk.GetMu()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get mu")
	}

	nMod, err := d.sk.GetNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get N residue params")
	}

	nnMod, err := d.sk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	cToLambda, err := nnMod.ModExp(cipherText.C, d.sk.Phi)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	l, err := d.sk.L(cToLambda)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute L")
	}

	m := new(saferith.Nat).ModMul(l, mu, nMod.GetModulus())
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

package ecelgamal

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.HomomorphicEncryptionKey[PlainText, Nonce, *CipherText, Scalar]             = (*SecretKey)(nil)
	_ indcpa.HomomorphicDecryptionKey[PlainText, Nonce, *CipherText, Scalar, *PublicKey] = (*SecretKey)(nil)
)

type SecretKey struct {
	PublicKey
	S curves.Scalar

	_ ds.Incomparable
}

func (sk *SecretKey) Decrypt(cipherText *CipherText) (PlainText, error) {
	s := cipherText.C1.ScalarMul(sk.S)
	m := cipherText.C2.Sub(s)
	return m, nil
}
func (*SecretKey) Open(_ *CipherText) (PlainText, Nonce, error) {
	return nil, nil, errs.NewFailed("Cannot open an encryption")
}

func (sk *SecretKey) ToEncryptionKey() (*PublicKey, error) {
	return &sk.PublicKey, nil
}

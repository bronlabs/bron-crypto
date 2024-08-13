package elgamalcommitment

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

type PublicKey struct {
	G curves.Point
	H curves.Point
}

type PlainText curves.Point

type Nonce curves.Scalar

type CipherText struct {
	C1 curves.Point
	C2 curves.Point
}

func EncryptWithNonce(pk *PublicKey, plainText PlainText, nonce Nonce) *CipherText {
	s := pk.H.ScalarMul(nonce)
	c1 := pk.G.ScalarMul(nonce)
	c2 := s.Add(plainText)

	return &CipherText{
		C1: c1,
		C2: c2,
	}
}

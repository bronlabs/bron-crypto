package rsa

import (
	nativeRsa "crypto/rsa"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type PublicKey struct {
	N *saferith.Modulus
	E uint64
}

type PrivateKey struct {
	PublicKey
	D *saferith.Nat
}

func GenKeys(prng io.Reader, bits int) (*PrivateKey, error) {
	nativeKey, err := nativeRsa.GenerateKey(prng, bits)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate RSA keys")
	}

	sk := &PrivateKey{
		PublicKey: PublicKey{
			N: saferith.ModulusFromNat(new(saferith.Nat).SetBig(nativeKey.N, nativeKey.N.BitLen())),
			E: uint64(nativeKey.E),
		},
		D: new(saferith.Nat).SetBig(nativeKey.D, nativeKey.N.BitLen()),
	}
	return sk, nil
}

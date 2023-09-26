package eddsa

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type Signature = schnorr.Signature

type PublicKey = schnorr.PublicKey

func Verify(suite *integration.CipherSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	if !schnorr.IsEd25519Compliant(suite) {
		return errs.NewVerificationFailed("unsupported cipher suite")
	}

	if err := schnorr.Verify(suite, publicKey, message, signature); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signature")
	}
	return nil
}

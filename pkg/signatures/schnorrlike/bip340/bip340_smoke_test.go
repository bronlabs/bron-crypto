package bip340_test

import (
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
)

var (
	_ signatures.Scheme[
		*bip340.PrivateKey, *bip340.PublicKey,
		bip340.Message, *bip340.Signature,
		*bip340.KeyGenerator, *bip340.Signer, *bip340.Verifier,
	] = (*bip340.Scheme)(nil)

	_ signatures.BatchVerifier[
		*bip340.PublicKey, bip340.Message, *bip340.Signature,
	] = (*bip340.Verifier)(nil)
)

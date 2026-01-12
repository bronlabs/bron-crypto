package mina_test

import (
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

var (
	_ signatures.Scheme[
		*mina.PrivateKey, *mina.PublicKey,
		*mina.Message, *mina.Signature,
		*mina.KeyGenerator, *mina.Signer, *mina.Verifier,
	] = (*mina.Scheme)(nil)
)

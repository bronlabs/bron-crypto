package paillier_test

import (
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

var _ encryption.Scheme[
	*paillier.PrivateKey,
	*paillier.PublicKey,
	*paillier.Plaintext,
	*paillier.Ciphertext,
	*paillier.Nonce,
	*paillier.KeyGenerator,
	*paillier.Encrypter,
	*paillier.Decrypter,
] = (*paillier.Scheme)(nil)

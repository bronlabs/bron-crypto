package paillier_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

var (
	_ encryption.Scheme[
		*paillier.PrivateKey,
		*paillier.PublicKey,
		*paillier.Plaintext,
		*paillier.Ciphertext,
		*paillier.Nonce,
		*paillier.KeyGenerator,
		*paillier.Encrypter,
		*paillier.Decrypter,
	] = (*paillier.Scheme)(nil)

	_ encryption.ShiftTypeCiphertext[
		*paillier.Ciphertext, *znstar.PaillierGroupElementUnknownOrder,
		*paillier.Plaintext,
		*paillier.PublicKey,
		*paillier.Nonce,
		*num.Nat,
	] = (*paillier.Ciphertext)(nil)

	_ encryption.GroupHomomorphicScheme[
		*paillier.PrivateKey,
		*paillier.PublicKey,
		*paillier.Plaintext, *num.Int,
		*paillier.Ciphertext, *znstar.PaillierGroupElementUnknownOrder,
		*paillier.Nonce, *znstar.RSAGroupElementUnknownOrder,
		*paillier.KeyGenerator,
		*paillier.Encrypter,
		*paillier.Decrypter,
		*num.Nat,
	] = (*paillier.Scheme)(nil)
)

package paillier_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

var (
	_ encryption.GroupHomomorphicEncryptionKey[
		*paillier.PublicKey,
		*paillier.Plaintext, *num.ZMod, *num.Uint,
		*paillier.Nonce, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
		*paillier.Ciphertext, *znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder,
		*num.Int,
	] = (*paillier.PublicKey)(nil)

	_ encryption.GroupHomomorphicDecryptionKey[
		*paillier.PublicKey,
		*paillier.SecretKey,
		*paillier.Plaintext, *num.ZMod, *num.Uint,
		*paillier.Nonce, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
		*paillier.Ciphertext, *znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder,
		*num.Int,
	] = (*paillier.SecretKey)(nil)

	_ encryption.OpeningKey[
		*paillier.PublicKey,
		*paillier.SecretKey,
		*paillier.Plaintext,
		*paillier.Nonce,
		*paillier.Ciphertext,
	] = (*paillier.SecretKey)(nil)
)

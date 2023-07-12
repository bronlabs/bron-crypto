package lindell17

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
)

type Shard struct {
	SigningKeyShare        *threshold.SigningKeyShare
	PaillierSecretKey      *paillier.SecretKey
	PaillierPublicKeys     map[integration.IdentityKey]*paillier.PublicKey
	PaillierEncryptedShare map[integration.IdentityKey]paillier.CipherText
}

package hashcommitments

import (
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"golang.org/x/crypto/sha3"
	"hash"
)

func CrsFromSessionId(sessionId []byte, dsts ...[]byte) []byte {
	hashFunc := func() hash.Hash {
		return sha3.NewCShake128([]byte("CRS"), sessionId)
	}
	return hashing.HashPrefixedLength(hashFunc, dsts...)
}

package noise

import (
	"crypto/cipher"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Signer struct {
	PublicKey  curves.Point
	PrivateKey curves.Scalar
}

type P2PMessage struct {
	Ne         curves.Point
	Ciphertext []byte
}

type CipherState struct {
	K     [32]byte
	Nonce uint64
}

type SymmetricState struct {
	Cs CipherState
	Ck [32]byte
	H  [32]byte
}

// MixKey is designed uses HKDF because:
// * HKDF is well-known and HKDF "chains" are used in similar ways in other protocols (e.g. Signal, IPsec, TLS 1.3).
// * HKDF has a published analysis.
// * HKDF applies multiple layers of hashing between each MixKey() input. This "extra" hashing might mitigate the impact of hash function weakness.
func (ss *SymmetricState) MixKey(hashFunc func() hash.Hash, ikm []byte) {
	ck, tempK := GetHkdf(hashFunc, ss.Ck, ikm)
	ss.Cs = InitializeKey(tempK)
	ss.Ck = ck
}

// MixHash is used instead of sending all inputs directly through MixKey() because:
// * is more efficient than MixKey().
// * produces a non-secret h value that might be useful to higher-level protocols, e.g. for channel-binding.
func (ss *SymmetricState) MixHash(hashFunc func() hash.Hash, data []byte) error {
	var err error
	ss.H, err = GetHash(hashFunc, ss.H[:], data)
	return err
}

type HandshakeState struct {
	Ss                    SymmetricState
	StaticKey             Signer
	EphemeralKey          Signer
	OtherPartyStaticPk    curves.Point
	OtherPartyEphemeralPk curves.Point
}

type Session struct {
	// handshake state
	Hs HandshakeState
	// hash output of the handshake
	H [32]byte
	// cs1 and cs2 are used to encrypt and decrypt messages
	Cs1 CipherState
	Cs2 CipherState
	// round number
	Round uint64
	// flag to indicate if this is the initializer or the responder
	IsInitializer bool
}

type Suite struct {
	Curve curves.Curve
	Hash  SupportedHash
	Aead  SupportedAEAD

	_ types.Incomparable
}

func (n *Suite) Validate() error {
	if n == nil {
		return errs.NewIsNil("noise suite is nil")
	}
	if n.Curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	if _, ok := SupportedHashes[n.Hash]; !ok {
		return errs.NewInvalidType("hash is not supported")
	}
	if _, ok := SupportedAeads[n.Aead]; !ok {
		return errs.NewInvalidType("aead is not supported")
	}
	return nil
}

func (n *Suite) GetHashFunc() func() hash.Hash {
	return SupportedHashes[n.Hash]
}

func (n *Suite) GetAeadFunc() func([]byte) cipher.AEAD {
	return SupportedAeads[n.Aead]
}

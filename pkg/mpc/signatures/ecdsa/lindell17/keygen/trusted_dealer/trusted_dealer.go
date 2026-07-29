package trusted_dealer

import (
	"io"
	"slices"
	"testing"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	baseDealer "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// DealRandom creates Lindell17 shards for the supplied monotone access
// structure. It encrypts every raw MSP share component once under its owner's
// Paillier public key and stores the vector with each qualified two-party peer
// so signing can convert it for the selected quorum. The dealer is trusted;
// this path does not produce the DKG package's LP or LPDL proofs. In production,
// keyLen must be at least base.IFCKeyLength and prng must be cryptographically
// secure.
func DealRandom[
	P curves.Point[P, B, S],
	B algebra.PrimeFieldElement[B],
	S algebra.PrimeFieldElement[S],
](
	curve ecdsa.Curve[P, B, S],
	accessStructure accessstructures.Monotone,
	keyLen uint,
	prng io.Reader,
) (ds.Map[sharing.ID, *lindell17.Shard[P, B, S]], *ecdsa.PublicKey[P, B, S], error) {
	if curve == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("curve is nil")
	}
	if accessStructure == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("access structure is nil")
	}
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	if keyLen < 1 {
		return nil, nil, ErrInvalidArgument.WithMessage("Paillier key length must be positive")
	}
	if !testing.Testing() && keyLen < base.IFCKeyLength {
		return nil, nil, ErrInvalidArgument.WithMessage("Paillier key length must be at least %d bits", base.IFCKeyLength)
	}

	baseShards, err := baseDealer.Deal(curve, accessStructure, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot deal base shards")
	}

	shareholderIDs := baseShards.Keys()
	slices.Sort(shareholderIDs)
	if len(shareholderIDs) == 0 {
		return nil, nil, ErrInvalidArgument.WithMessage("access structure has no shareholders")
	}

	paillierSecretKeys := make(map[sharing.ID]*paillier.SecretKey, len(shareholderIDs))
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey, len(shareholderIDs))
	encryptedShares := make(map[sharing.ID][]*paillier.Ciphertext, len(shareholderIDs))
	for _, id := range shareholderIDs {
		secretKey, err := paillier.SampleSecretKey(keyLen, prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot generate Paillier secret key for shareholder %d", id)
		}
		paillierSecretKeys[id] = secretKey
		paillierPublicKeys[id] = secretKey.Public()

		baseShard, _ := baseShards.Get(id)
		shareValues := baseShard.Share().Value()
		encryptedShares[id] = make([]*paillier.Ciphertext, len(shareValues))
		for i, shareValue := range shareValues {
			ciphertext, err := encryptScalar(shareValue, paillierPublicKeys[id], prng)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt share component %d for shareholder %d", i, id)
			}
			encryptedShares[id][i] = ciphertext
		}
	}

	shards := hashmap.NewComparable[sharing.ID, *lindell17.Shard[P, B, S]]()
	var publicKey *ecdsa.PublicKey[P, B, S]
	for _, id := range shareholderIDs {
		baseShard, _ := baseShards.Get(id)
		otherPublicKeys := hashmap.NewComparable[sharing.ID, *paillier.PublicKey]()
		otherEncryptedShares := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
		for _, otherID := range shareholderIDs {
			if otherID == id || !baseShard.MSP().Accepts(id, otherID) {
				continue
			}
			otherPublicKeys.Put(otherID, paillierPublicKeys[otherID])
			otherEncryptedShares.Put(otherID, slices.Clone(encryptedShares[otherID]))
		}

		auxInfo, err := lindell17.NewAuxiliaryInfo(
			paillierSecretKeys[id],
			otherPublicKeys.Freeze(),
			otherEncryptedShares.Freeze(),
		)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create auxiliary information for shareholder %d", id)
		}
		shard, err := lindell17.NewShard(
			baseShard,
			auxInfo,
		)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create Lindell17 shard for shareholder %d", id)
		}
		shards.Put(id, shard)

		if publicKey == nil {
			publicKey, err = ecdsa.NewPublicKey(baseShard.PublicKeyValue())
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot create ECDSA public key")
			}
		}
	}
	return shards.Freeze(), publicKey, nil
}

func encryptScalar[S algebra.PrimeFieldElement[S]](
	value S,
	publicKey *paillier.PublicKey,
	prng io.Reader,
) (*paillier.Ciphertext, error) {
	valueNat, err := num.N().FromBytes(value.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert share component to a natural number")
	}
	plaintext, err := paillier.NewPlaintextFromNat(valueNat, publicKey.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Paillier plaintext for share component")
	}
	nonce, err := publicKey.SampleNonce(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample Paillier nonce for share component")
	}
	ciphertext, err := publicKey.EncryptWithNonce(plaintext, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt share component")
	}
	return ciphertext, nil
}

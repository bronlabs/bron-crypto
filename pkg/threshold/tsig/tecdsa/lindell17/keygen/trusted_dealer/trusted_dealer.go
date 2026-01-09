package trusted_dealer

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
)

// DealRandom creates Lindell17 shards using a trusted dealer.
func DealRandom[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], shareholder ds.Set[sharing.ID], keyLen uint, prng io.Reader) (ds.Map[sharing.ID, *lindell17.Shard[P, B, S]], *ecdsa.PublicKey[P, B, S], error) {
	if curve == nil || shareholder == nil || shareholder.Size() == 0 || prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid input to trusted dealer")
	}
	feldmanDealer, err := feldman.NewScheme(curve.Generator(), 2, shareholder)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("could not create shamir scheme")
	}

	feldmanOutput, secret, err := feldmanDealer.DealRandom(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("could not deal shares")
	}
	publicKey, err := ecdsa.NewPublicKey(curve.ScalarBaseMul(secret.Value()))
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create ecdsa public key")
	}

	scheme := paillier.NewScheme()

	paillierPrivateKeys := make(map[sharing.ID]*paillier.PrivateKey)
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey)
	shareCiphertexts := make(map[sharing.ID]*paillier.Ciphertext)

	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create paillier key generator")
	}

	for id, share := range feldmanOutput.Shares().Iter() {
		paillierPrivateKeys[id], paillierPublicKeys[id], err = keyGenerator.Generate(prng)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot generate paillier keypair")
		}
		sharePlaintext, err := paillierPublicKeys[id].PlaintextSpace().FromBytes(share.Bytes())
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot create paillier plaintext from share bytes")
		}

		encrypter, err := scheme.SelfEncrypter(paillierPrivateKeys[id])
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot create paillier encrypter")
		}

		shareCiphertexts[id], _, err = encrypter.SelfEncrypt(sharePlaintext, prng)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot encrypt share under paillier public key")
		}
	}

	shards := make(map[sharing.ID]*lindell17.Shard[P, B, S])
	for id := range feldmanOutput.Shares().Iter() {
		ppks := maps.Clone(paillierPublicKeys)
		delete(ppks, id)
		encs := maps.Clone(shareCiphertexts)
		delete(encs, id)

		auxInfo, err := lindell17.NewAuxiliaryInfo(
			paillierPrivateKeys[id],
			hashmap.NewComparableFromNativeLike(ppks).Freeze(),
			hashmap.NewComparableFromNativeLike(encs).Freeze(),
		)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot create auxiliary info")
		}

		share, exists := feldmanOutput.Shares().Get(id)
		if !exists {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot get share for shareholder %d", id)
		}
		baseShard, err := tecdsa.NewShard(share, feldmanOutput.VerificationMaterial(), feldmanDealer.AccessStructure())
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot create tECDSA Lindell17 shard")
		}

		shards[id], err = lindell17.NewShard(baseShard, auxInfo)
		if err != nil {
			return nil, nil, errs2.Wrap(err).WithMessage("cannot create lindell17 shard")
		}
	}
	return hashmap.NewComparableFromNativeLike(shards).Freeze(), publicKey, nil
}

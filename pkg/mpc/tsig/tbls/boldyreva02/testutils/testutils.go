package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	gentu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls/boldyreva02/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls/boldyreva02/signing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/errs-go/errs"
	"github.com/stretchr/testify/require"
)

// Type aliases for convenience.
type ShortKeyShard = boldyreva02.Shard[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
type LongKeyShard = boldyreva02.Shard[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]

// DoBoldyrevaDKG runs the complete DKG process for Boldyreva02 threshold BLS
// It uses Gennaro DKG under the hood and converts the output to BLS shards.
func DoBoldyrevaDKG[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB, participants map[sharing.ID]*gennaro.Participant[PK, S], shortKey bool,
) (
	shards map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S],
) {
	tb.Helper()
	var err error

	// Run Gennaro DKG
	dkgOutputs := gentu.DoGennaroDKG(tb, participants)

	// Convert DKG outputs to BLS shards
	shards = make(map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S])
	for id, output := range dkgOutputs {
		var shard *tbls.Shard[PK, PKFE, SG, SGFE, E, S]
		if shortKey {
			shard, err = keygen.NewShortKeyShard(output)
		} else {
			shard, err = keygen.NewLongKeyShard(output)
		}
		require.NoError(tb, err)

		shards[id] = shard
	}

	return shards
}

// ProducePartialSignatures produces partial signatures from all cosigners.
func ProducePartialSignatures[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	cosigners []*signing.Cosigner[PK, PKFE, SG, SGFE, E, S], message []byte,
) (
	partialSigs map[sharing.ID]*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S], err error,
) {
	partialSigs = make(map[sharing.ID]*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S], len(cosigners))
	for _, cosigner := range cosigners {
		partialSigs[cosigner.SharingID()], err = cosigner.ProducePartialSignature(message)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("%d could not produce partial signature", cosigner.SharingID())
		}
	}
	return partialSigs, nil
}

// DoThresholdSign performs the complete threshold signing process.
func DoThresholdSign[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB,
	cosigners []*signing.Cosigner[PK, PKFE, SG, SGFE, E, S],
	scheme *bls.Scheme[PK, PKFE, SG, SGFE, E, S],
	message []byte,
	aggregator *signing.Aggregator[PK, PKFE, SG, SGFE, E, S],
) (
	signature *bls.Signature[SG, SGFE, PK, PKFE, E, S], err error,
) {
	tb.Helper()

	// Produce partial signatures
	partialSigs, err := ProducePartialSignatures(cosigners, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not produce partial signatures")
	}

	// Convert map to RoundMessages
	partialSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]]()
	for id, psig := range partialSigs {
		partialSigsMap.Put(id, ntu.CBORRoundTrip(tb, psig))
	}
	roundMessages := partialSigsMap.Freeze()

	// Aggregate partial signatures using the provided aggregator
	signature, err = aggregator.Aggregate(roundMessages, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not aggregate partial signatures")
	}

	return signature, nil
}

// VerifyPartialSignatures verifies all partial signatures.
func VerifyPartialSignatures[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB,
	partialSigs map[sharing.ID]*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S],
	publicMaterial *tbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S],
	scheme *bls.Scheme[PK, PKFE, SG, SGFE, E, S],
	message []byte,
) error {
	tb.Helper()

	qualifiedSet := hashset.NewComparable[sharing.ID]()
	for id := range partialSigs {
		qualifiedSet.Add(id)
	}
	quorum, err := unanimity.NewUnanimityAccessStructure(qualifiedSet.Freeze())
	require.NoError(tb, err)

	for id, psig := range partialSigs {
		publicKeyShare, exists := publicMaterial.PublicKeyValueShares().Get(id)
		if !exists {
			return errs.New("partial public key for participant %d", id)
		}
		additivePublicKeyShare, err := publicKeyShare.ToAdditive(quorum)
		require.NoError(tb, err)
		partialPublicKey, err := bls.NewPublicKey(additivePublicKeyShare.Value())
		require.NoError(tb, err)

		// Determine the message to verify based on rogue key prevention algorithm
		var verifyMessage []byte
		switch scheme.RogueKeyPreventionAlgorithm() {
		case bls.Basic:
			verifyMessage = message
		case bls.MessageAugmentation:
			verifyMessage, err = bls.AugmentMessage(message, publicMaterial.PublicKey().Value())
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to augment message for participant %d", id)
			}
		case bls.POP:
			verifyMessage = message
		}

		// Create verifier
		verifier, err := scheme.Verifier()
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to create verifier")
		}

		// Verify the partial signature
		if psig.SigmaI != nil {
			if err := verifier.Verify(psig.SigmaI, partialPublicKey, verifyMessage); err != nil {
				return errs.Wrap(err).WithMessage("failed to verify partial signature from participant %d", id)
			}
		}

		// Verify the proof of possession if present
		if scheme.RogueKeyPreventionAlgorithm() == bls.POP && psig.SigmaPopI != nil {
			popMessage := partialPublicKey.Bytes()
			popDst := scheme.CipherSuite().GetPopDst(scheme.Variant())
			popVerifier, err := scheme.Verifier(bls.VerifyWithCustomDST[PK](popDst))
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to create POP verifier")
			}
			if err := popVerifier.Verify(psig.SigmaPopI, partialPublicKey, popMessage); err != nil {
				return errs.Wrap(err).WithMessage("failed to verify proof of possession from participant %d", id)
			}
		}
	}
	return nil
}

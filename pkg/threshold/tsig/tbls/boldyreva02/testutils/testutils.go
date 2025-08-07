package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	gentu "github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02/keygen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02/signing"
)

// Type aliases for convenience
type ShortKeyShard = boldyreva02.Shard[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
type LongKeyShard = boldyreva02.Shard[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]

// DoBoldyrevaDKG runs the complete DKG process for Boldyreva02 threshold BLS
// It uses Gennaro DKG under the hood and converts the output to BLS shards
func DoBoldyrevaDKG[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB, participants []*gennaro.Participant[PK, S], shortKey bool,
) (
	shards ds.MutableMap[sharing.ID, *tbls.Shard[PK, PKFE, SG, SGFE, E, S]], err error,
) {
	tb.Helper()

	// Run Gennaro DKG
	dkgOutputs, err := gentu.DoGennaroDKG(tb, participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run Gennaro DKG")
	}

	// Convert DKG outputs to BLS shards
	shards = hashmap.NewComparable[sharing.ID, *tbls.Shard[PK, PKFE, SG, SGFE, E, S]]()
	for id, output := range dkgOutputs.Iter() {
		var shard *tbls.Shard[PK, PKFE, SG, SGFE, E, S]
		if shortKey {
			shard, err = keygen.NewShortKeyShard(output)
		} else {
			shard, err = keygen.NewLongKeyShard(output)
		}
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create shard for participant %d", id)
		}
		shards.Put(id, shard)
	}

	return shards, nil
}

// ProducePartialSignatures produces partial signatures from all cosigners
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
			return nil, errs.WrapFailed(err, "%d could not produce partial signature", cosigner.SharingID())
		}
	}
	return partialSigs, nil
}

// DoThresholdSign performs the complete threshold signing process
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
		return nil, errs.WrapFailed(err, "could not produce partial signatures")
	}

	// Convert map to RoundMessages
	partialSigsMap := hashmap.NewComparable[sharing.ID, *boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]]()
	for id, psig := range partialSigs {
		partialSigsMap.Put(id, psig)
	}
	roundMessages := partialSigsMap.Freeze()

	// Aggregate partial signatures using the provided aggregator
	signature, err = aggregator.Aggregate(roundMessages, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	return signature, nil
}

// VerifyPartialSignatures verifies all partial signatures
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

	for id, psig := range partialSigs {
		partialPK, exists := publicMaterial.PartialPublicKeys().Get(id)
		if !exists {
			return errs.NewMissing("partial public key for participant %d", id)
		}

		// Determine the message to verify based on rogue key prevention algorithm
		var verifyMessage []byte
		var err error
		switch scheme.RogueKeyPreventionAlgorithm() {
		case bls.Basic:
			verifyMessage = message
		case bls.MessageAugmentation:
			verifyMessage, err = bls.AugmentMessage(message, publicMaterial.PublicKey().Value())
			if err != nil {
				return errs.WrapFailed(err, "failed to augment message for participant %d", id)
			}
		case bls.POP:
			verifyMessage = message
		}

		// Create verifier
		verifier, err := scheme.Verifier()
		if err != nil {
			return errs.WrapFailed(err, "failed to create verifier")
		}

		// Verify the partial signature
		if psig.SigmaI != nil {
			if err := verifier.Verify(psig.SigmaI, partialPK, verifyMessage); err != nil {
				return errs.WrapFailed(err, "failed to verify partial signature from participant %d", id)
			}
		}

		// Verify the proof of possession if present
		if scheme.RogueKeyPreventionAlgorithm() == bls.POP && psig.SigmaPopI != nil {
			popMessage := partialPK.Bytes()
			popDst := scheme.CipherSuite().GetPopDst(scheme.Variant())
			popVerifier, err := scheme.Verifier(bls.VerifyWithCustomDST[PK](popDst))
			if err != nil {
				return errs.WrapFailed(err, "failed to create POP verifier")
			}
			if err := popVerifier.Verify(psig.SigmaPopI, partialPK, popMessage); err != nil {
				return errs.WrapFailed(err, "failed to verify proof of possession from participant %d", id)
			}
		}
	}

	return nil
}

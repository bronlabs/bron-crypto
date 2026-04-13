package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro"
	gentu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro/testutils"
	tbls "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02/signing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/errs-go/errs"
	"github.com/stretchr/testify/require"
)

// Type aliases for convenience.
type ShortKeyShard = boldyreva02.Shard[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
type LongKeyShard = boldyreva02.Shard[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.GtElement, *bls12381.Scalar]

// DoBoldyrevaDKGShort runs the complete DKG process for Boldyreva02 BLS in the
// short key variant (public keys in G1, signatures in G2). It uses Gennaro DKG
// under the hood and converts the output to short key BLS shards.
func DoBoldyrevaDKGShort[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.PrimeFieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB, participants map[sharing.ID]*gennaro.Participant[PK, S],
) (
	shards map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S],
) {
	tb.Helper()

	dkgOutputs := gentu.DoGennaroDKG(tb, participants)

	shards = make(map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S])
	for id, output := range dkgOutputs {
		shard, err := keygen.NewShortKeyShard(output)
		require.NoError(tb, err)
		shards[id] = shard
	}

	return shards
}

// DoBoldyrevaDKGLong runs the complete DKG process for Boldyreva02 BLS in the
// long key variant (public keys in G2, signatures in G1). It uses Gennaro DKG
// under the hood and converts the output to long key BLS shards.
func DoBoldyrevaDKGLong[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.PrimeFieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB, participants map[sharing.ID]*gennaro.Participant[PK, S],
) (
	shards map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S],
) {
	tb.Helper()

	dkgOutputs := gentu.DoGennaroDKG(tb, participants)

	shards = make(map[sharing.ID]*tbls.Shard[PK, PKFE, SG, SGFE, E, S])
	for id, output := range dkgOutputs {
		shard, err := keygen.NewLongKeyShard(output)
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

// DoThresholdSign performs the complete signing process.
func DoThresholdSign[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	tb testing.TB,
	cosigners []*signing.Cosigner[PK, PKFE, SG, SGFE, E, S],
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

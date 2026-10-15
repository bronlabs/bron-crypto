package signing_test

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/dkg/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/signing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

var testAccessStructure = []int{2, 3}
var testHashFuncs = []crypto.Hash{crypto.SHA256, crypto.BLAKE2b_512}

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, total := range testAccessStructure {
		t.Run(fmt.Sprintf("total=%d", total), func(t *testing.T) {
			t.Parallel()
			for _, ch := range testHashFuncs {
				t.Run(fmt.Sprintf("hash func=%s", ch.String()), func(t *testing.T) {
					t.Parallel()
					hashFunc := ch.New
					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						curve := k256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPath(t, total, suite)
					})
					t.Run("P256", func(t *testing.T) {
						t.Parallel()
						curve := p256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPath(t, total, suite)
					})
				})
			}
		})
	}
}

func TestHappyPathWithDKG(t *testing.T) {
	t.Parallel()

	for _, total := range testAccessStructure {
		t.Run(fmt.Sprintf("total=%d", total), func(t *testing.T) {
			t.Parallel()
			for _, ch := range testHashFuncs {
				t.Run(fmt.Sprintf("hash func=%s", ch.String()), func(t *testing.T) {
					t.Parallel()
					hashFunc := ch.New
					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						curve := k256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPathWithDKG(t, total, suite)
					})
					t.Run("P256", func(t *testing.T) {
						t.Parallel()
						curve := p256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPathWithDKG(t, total, suite)
					})
				})
			}
		})
	}
}

func TestHappyPathWithDKG_NonIdealCNF2Of3(t *testing.T) {
	t.Parallel()

	accessStructure, err := cnf.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1).Freeze(),
		hashset.NewComparable[sharing.ID](2).Freeze(),
		hashset.NewComparable[sharing.ID](3).Freeze(),
	)
	require.NoError(t, err)

	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)
	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.False(t, shards[1].MSP().IsIdeal(), "CNF encoding of 2-of-3 must exercise multi-component shares")

	publicKey, err := ecdsa.NewPublicKey(shards[1].PublicKeyValue())
	require.NoError(t, err)
	testAllQualifiedPairs(t, suite, accessStructure, shards, publicKey)
}

func TestHappyPathNonIdealNonThresholdCNF(t *testing.T) {
	t.Parallel()

	// These are maximal unqualified sets. The resulting policy is genuinely
	// non-threshold: {1,4} is qualified, while the equally sized {1,2} is not.
	accessStructure, err := cnf.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	)
	require.NoError(t, err)
	require.True(t, accessStructure.IsQualified(1, 4))
	require.False(t, accessStructure.IsQualified(1, 2))

	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)
	dealtShards, publicKey, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, pcg.NewRandomised())
	require.NoError(t, err)

	shards := make(map[sharing.ID]*lindell17.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], dealtShards.Size())
	for id, shard := range dealtShards.Iter() {
		shards[id] = shard
	}
	require.False(t, shards[1].MSP().IsIdeal())
	require.Len(t, shards[1].Share().Value(), 2)
	require.Len(t, shards[4].Share().Value(), 2)

	// Both cosigners hold multiple MSP components, so this one signing flow
	// exercises local conversion on both sides and encrypted conversion for the
	// primary share.
	runSigning(t, suite, shards, publicKey, 1, 4)
}

func TestNewCosignerRejectsInexactTwoPartyContext(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards, _, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, prng)
	require.NoError(t, err)
	shard1, ok := shards.Get(1)
	require.True(t, ok)
	shard2, ok := shards.Get(2)
	require.True(t, ok)

	threePartyContexts := session_testutils.MakeRandomContexts(t, shareholders, prng)
	_, err = signing.NewPrimaryCosigner(threePartyContexts[1], suite, 2, shard1, fischlin.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)

	twoPartyContexts := session_testutils.MakeRandomContexts(t, hashset.NewComparable[sharing.ID](1, 2).Freeze(), prng)
	_, err = signing.NewPrimaryCosigner(twoPartyContexts[1], suite, 3, shard1, fischlin.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)

	_, err = signing.NewPrimaryCosigner(twoPartyContexts[1], suite, 1, shard2, fischlin.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)

	missingPairMaterialShard := &lindell17.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{
		BaseShard: shard2.BaseShard,
	}
	_, err = signing.NewSecondaryCosigner(twoPartyContexts[2], suite, 1, missingPairMaterialShard, fischlin.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)

	malformedEncryptedShares := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	for id, ciphertexts := range shard2.EncryptedShares().Iter() {
		ciphertexts = slices.Clone(ciphertexts)
		if id == 1 {
			ciphertexts = append(ciphertexts, ciphertexts[0])
		}
		malformedEncryptedShares.Put(id, ciphertexts)
	}
	malformedAuxiliaryInfo, err := lindell17.NewAuxiliaryInfo(
		shard2.PaillierSecretKey(),
		shard2.PaillierPublicKeys(),
		malformedEncryptedShares.Freeze(),
	)
	require.NoError(t, err)
	malformedComponentCountShard := &lindell17.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{
		BaseShard:     shard2.BaseShard,
		AuxiliaryInfo: *malformedAuxiliaryInfo,
	}
	malformedContexts := session_testutils.MakeRandomContexts(t, hashset.NewComparable[sharing.ID](1, 2).Freeze(), prng)
	_, err = signing.NewSecondaryCosigner(malformedContexts[2], suite, 1, malformedComponentCountShard, fischlin.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)
}

func TestNewCosignerRequiresStraightLineCompiler(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)
	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards, _, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, prng)
	require.NoError(t, err)
	primaryShard, ok := shards.Get(1)
	require.True(t, ok)

	for _, niCompiler := range []compiler.Name{fischlin.Name, randfischlin.Name} {
		contexts := session_testutils.MakeRandomContexts(t, shareholders, prng)
		_, err = signing.NewPrimaryCosigner(contexts[1], suite, 2, primaryShard, niCompiler, pcg.NewRandomised())
		require.NoError(t, err)
	}

	contexts := session_testutils.MakeRandomContexts(t, shareholders, prng)
	_, err = signing.NewPrimaryCosigner(contexts[1], suite, 2, primaryShard, fiatshamir.Name, pcg.NewRandomised())
	require.ErrorIs(t, err, signing.ErrInvalidArgument)
	require.Contains(t, fmt.Sprintf("%+v", err), "Lindell17 signing requires a straight-line extractable compiler")
}

func TestMessageToScalarRejectsNilSuite(t *testing.T) {
	t.Parallel()

	t.Run("K256", func(t *testing.T) {
		t.Parallel()

		_, err := signing.MessageToScalar[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](nil, []byte("message"))
		require.ErrorIs(t, err, signing.ErrInvalidArgument)
	})
	t.Run("P256", func(t *testing.T) {
		t.Parallel()

		_, err := signing.MessageToScalar[*p256.Point, *p256.BaseFieldElement, *p256.Scalar](nil, []byte("message"))
		require.ErrorIs(t, err, signing.ErrInvalidArgument)
	})
}

func TestCalcC3ConvertsLiftedMSPComponentsWithoutAggregatedScaling(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	field := curve.ScalarField()
	secretKey, err := paillier.SampleSecretKey(1024, prng)
	require.NoError(t, err)
	publicKey := secretKey.Public()

	components := []*k256.Scalar{
		field.FromUint64(5),
		field.FromUint64(11),
		field.FromUint64(17),
	}
	coefficients := []*k256.Scalar{
		field.One().Neg(),
		field.FromUint64(2),
		field.FromUint64(7),
	}
	q, err := num.Z().FromCardinal(curve.Order())
	require.NoError(t, err)
	twoQ := q.Mul(num.Z().FromUint64(2))
	encryptedComponents := make([]*paillier.Ciphertext, len(components))
	for i, component := range components {
		componentInt, err := num.Z().FromUnsignedNumeric(component)
		require.NoError(t, err)
		liftedComponent := twoQ.Add(componentInt)
		require.True(t, q.Compare(liftedComponent).IsLessThan(), "component must exercise a non-canonical q-lift")
		plaintext, err := paillier.NewPlaintextSymmetric(liftedComponent, publicKey.PlaintextGroup().Modulus())
		require.NoError(t, err)
		encryptedComponents[i], _, err = encryption.Encrypt(plaintext, publicKey, prng)
		require.NoError(t, err)
	}

	k2 := field.FromUint64(3)
	mPrime := field.FromUint64(13)
	r := field.FromUint64(19)
	secondaryShare := field.FromUint64(23)
	secondaryZeroShare := field.FromUint64(29)
	refreshedSecondaryShare := secondaryShare.Add(secondaryZeroShare)
	primaryZeroShare := secondaryZeroShare.Neg()
	c3, err := signing.CalcC3(
		k2,
		mPrime,
		r,
		refreshedSecondaryShare,
		primaryZeroShare,
		curve.Order(),
		publicKey,
		encryptedComponents,
		coefficients,
		prng,
	)
	require.NoError(t, err)

	plaintext, err := secretKey.Decrypt(c3)
	require.NoError(t, err)
	integer := plaintext.Normalise()
	actual, err := field.FromBytesBEReduce(integer.Abs().BytesBE())
	require.NoError(t, err)
	if integer.IsNegative() {
		actual = actual.Neg()
	}
	primaryShare := field.Zero()
	for i, component := range components {
		primaryShare = primaryShare.Add(coefficients[i].Mul(component))
	}
	k2Inv, err := k2.TryInv()
	require.NoError(t, err)
	expected := k2Inv.Mul(mPrime.Add(r.Mul(primaryShare.Add(secondaryShare))))
	require.True(t, actual.Equal(expected))

	_, err = signing.CalcC3(
		k2,
		mPrime,
		r,
		refreshedSecondaryShare,
		primaryZeroShare,
		curve.Order(),
		publicKey,
		encryptedComponents,
		coefficients[:len(coefficients)-1],
		prng,
	)
	require.ErrorIs(t, err, signing.ErrInvalidArgument)
}

func TestCalcC3RejectsPaillierModulusBelowNoWrapBound(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	field := curve.ScalarField()
	secretKey, err := paillier.SampleSecretKey(512, prng)
	require.NoError(t, err)
	publicKey := secretKey.Public()
	plaintext, err := paillier.NewPlaintextSymmetric(num.Z().FromUint64(1), publicKey.PlaintextGroup().Modulus())
	require.NoError(t, err)
	ciphertext, _, err := encryption.Encrypt(plaintext, publicKey, prng)
	require.NoError(t, err)

	_, err = signing.CalcC3(
		field.FromUint64(3),
		field.FromUint64(5),
		field.FromUint64(7),
		field.FromUint64(11),
		field.FromUint64(13),
		curve.Order(),
		publicKey,
		[]*paillier.Ciphertext{ciphertext},
		[]*k256.Scalar{field.One()},
		prng,
	)
	require.ErrorIs(t, err, signing.ErrInvalidArgument)
}

func TestSigningRejectsNullNIZKProof(t *testing.T) {
	t.Parallel()

	t.Run("round 2", func(t *testing.T) {
		t.Parallel()

		primary, secondary := newK256FischlinCosigners(t)
		round1Output, err := primary.Round1()
		require.NoError(t, err)
		round2Output, err := secondary.Round2(round1Output)
		require.NoError(t, err)
		round2Output.BigR2Proof = []byte{0xf6}

		require.NotPanics(t, func() {
			_, err = primary.Round3(round2Output)
		})
		require.ErrorIs(t, err, proofs.ErrInvalidArgument)
		culprit, ok := errs.HasTag(err, base.IdentifiableAbortPartyIDTag)
		require.True(t, ok)
		require.Equal(t, sharing.ID(2), culprit)
	})

	t.Run("round 3", func(t *testing.T) {
		t.Parallel()

		primary, secondary := newK256FischlinCosigners(t)
		round1Output, err := primary.Round1()
		require.NoError(t, err)
		round2Output, err := secondary.Round2(round1Output)
		require.NoError(t, err)
		round3Output, err := primary.Round3(round2Output)
		require.NoError(t, err)
		bigR1Proof := slices.Clone(round3Output.BigR1Proof)
		round3Output.BigR1Proof = slices.Clone(round2Output.BigR2Proof)
		_, err = secondary.Round4(round3Output, []byte("committed-proof regression"))
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)

		round3Output.BigR1Proof = bigR1Proof
		_, err = secondary.Round4(round3Output, []byte("valid-proof regression"))
		require.NoError(t, err)
	})
}

func newK256FischlinCosigners(tb testing.TB) (
	*signing.PrimaryCosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar],
	*signing.SecondaryCosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar],
) {
	tb.Helper()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(tb, err)
	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(tb, err)
	shards, _, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, prng)
	require.NoError(tb, err)
	primaryShard, ok := shards.Get(1)
	require.True(tb, ok)
	secondaryShard, ok := shards.Get(2)
	require.True(tb, ok)
	contexts := session_testutils.MakeRandomContexts(tb, shareholders, prng)
	primary, err := signing.NewPrimaryCosigner(contexts[1], suite, 2, primaryShard, fischlin.Name, pcg.NewRandomised())
	require.NoError(tb, err)
	secondary, err := signing.NewSecondaryCosigner(contexts[2], suite, 1, secondaryShard, fischlin.Name, pcg.NewRandomised())
	require.NoError(tb, err)
	return primary, secondary
}

func testHappyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, total int, suite *ecdsa.Suite[P, B, S]) {
	t.Helper()

	prng := pcg.NewRandomised()
	shareholders := sharing.NewOrdinalShareholderSet(uint(total))
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards, publicKey, err := trusted_dealer.DealRandom(suite.Curve(), accessStructure, base.IFCKeyLength, prng)
	require.NoError(t, err)

	nativeShards := make(map[sharing.ID]*lindell17.Shard[P, B, S], shards.Size())
	for id, shard := range shards.Iter() {
		nativeShards[id] = shard
	}
	testAllQualifiedPairs(t, suite, accessStructure, nativeShards, publicKey)
}

func testHappyPathWithDKG[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, total int, suite *ecdsa.Suite[P, B, S]) {
	tb.Helper()

	shareholders := sharing.NewOrdinalShareholderSet(uint(total))
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(tb, err)
	shards := testutils.RunLindell17DKG(tb, suite.Curve(), accessStructure)
	publicKey, err := ecdsa.NewPublicKey(shards[shareholders.List()[0]].PublicKeyValue())
	require.NoError(tb, err)
	testAllQualifiedPairs(tb, suite, accessStructure, shards, publicKey)
}

func testAllQualifiedPairs[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	suite *ecdsa.Suite[P, B, S],
	accessStructure accessstructures.Monotone,
	shards map[sharing.ID]*lindell17.Shard[P, B, S],
	publicKey *ecdsa.PublicKey[P, B, S],
) {
	tb.Helper()

	for pair := range sliceutils.Combinations(accessStructure.Shareholders().List(), 2) {
		if !accessStructure.IsQualified(pair...) {
			continue
		}
		for _, roles := range [][2]sharing.ID{{pair[0], pair[1]}, {pair[1], pair[0]}} {
			runSigning(tb, suite, shards, publicKey, roles[0], roles[1])
		}
	}
}

func runSigning[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	suite *ecdsa.Suite[P, B, S],
	shards map[sharing.ID]*lindell17.Shard[P, B, S],
	publicKey *ecdsa.PublicKey[P, B, S],
	primaryID, secondaryID sharing.ID,
) {
	tb.Helper()

	primaryShard, ok := shards[primaryID]
	require.True(tb, ok)
	secondaryShard, ok := shards[secondaryID]
	require.True(tb, ok)
	encryptedPrimaryShares, ok := secondaryShard.EncryptedShares().Get(primaryID)
	require.True(tb, ok, "secondary=%d has no encrypted pair share for primary=%d", secondaryID, primaryID)
	require.Len(tb, encryptedPrimaryShares, len(primaryShard.Share().Value()))

	prng := pcg.NewRandomised()
	ctxs := session_testutils.MakeRandomContexts(tb, hashset.NewComparable(primaryID, secondaryID).Freeze(), prng)
	primaryCosigner, err := signing.NewPrimaryCosigner(ctxs[primaryID], suite, secondaryID, primaryShard, fischlin.Name, pcg.NewRandomised())
	require.NoError(tb, err, "primary=%d secondary=%d", primaryID, secondaryID)
	secondaryCosigner, err := signing.NewSecondaryCosigner(ctxs[secondaryID], suite, primaryID, secondaryShard, fischlin.Name, pcg.NewRandomised())
	require.NoError(tb, err, "primary=%d secondary=%d", primaryID, secondaryID)

	message := []byte(fmt.Sprintf("hello world from primary %d to secondary %d", primaryID, secondaryID))
	r1, err := primaryCosigner.Round1()
	require.NoError(tb, err)
	r2, err := secondaryCosigner.Round2(ntu.CBORRoundTrip(tb, r1))
	require.NoError(tb, err)
	r3, err := primaryCosigner.Round3(ntu.CBORRoundTrip(tb, r2))
	require.NoError(tb, err)
	r4, err := secondaryCosigner.Round4(ntu.CBORRoundTrip(tb, r3), message)
	require.NoError(tb, err)
	signature, err := primaryCosigner.Round5(ntu.CBORRoundTrip(tb, r4), message)
	require.NoError(tb, err)

	verifier, err := ecdsa.NewVerifier(suite)
	require.NoError(tb, err)
	err = verifier.Verify(ntu.CBORRoundTrip(tb, signature), publicKey, message)
	require.NoError(tb, err, "primary=%d secondary=%d", primaryID, secondaryID)

	primaryTapeCheck, err := ctxs[primaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	secondaryTapeCheck, err := ctxs[secondaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(primaryTapeCheck, secondaryTapeCheck))
}

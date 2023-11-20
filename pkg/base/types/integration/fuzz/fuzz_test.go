package fuzz

import (
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test_ChiperSuiteValidate(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		err := cipherSuite.Validate()
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_CohortValidate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, curveIndex uint, hashIndex uint, a uint64, b uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		fz := fuzz.NewFromGoFuzz(data).NilChance(0.05)
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		identityA, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(a))
		identityB, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(b))
		cc := integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB}),
			Protocol:     nil,
		}
		fz.Fuzz(&cc.Protocol)
		if cc.Protocol != nil {
			cc.Protocol.SignatureAggregators = hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB})
		}
		err := cc.Validate()
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_IsCohort(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, curveIndex uint, hashIndex uint, a uint64, b uint64, c uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		fz := fuzz.NewFromGoFuzz(data).NilChance(0.05)
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		identityA, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(a))
		identityB, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(b))
		identityC, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(c))
		cc := integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB}),
			Protocol:     nil,
		}
		fz.Fuzz(&cc.Protocol)
		if cc.Protocol != nil {
			cc.Protocol.SignatureAggregators = hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB})
		}
		cc.IsInCohort(identityC)
	})
}

func Fuzz_Test_IsAggregator(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, curveIndex uint, hashIndex uint, a uint64, b uint64, c uint64) {
		fz := fuzz.NewFromGoFuzz(data).NilChance(0.05)
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		identityA, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(a))
		identityB, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(b))
		identityC, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(c))
		cc := integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB}),
			Protocol:     nil,
		}
		fz.Fuzz(&cc.Protocol)
		if cc.Protocol != nil {
			cc.Protocol.SignatureAggregators = hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{identityA, identityB})
		}
		cc.IsSignatureAggregator(identityC)
	})
}

func Fuzz_Test_DeriveSharingId(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, a uint64, b uint64, c uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		identityA, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(a))
		identityB, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(b))
		identityC, _ := testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(c))
		integration.DeriveSharingIds(identityA.(integration.AuthKey), hashset.NewHashSet([]integration.IdentityKey{identityA, identityB, identityC}))
	})
}

func Fuzz_Test_RandomNat(f *testing.F) {
	f.Fuzz(func(t *testing.T, randomSeed uint64, a uint64, b uint64) {
		prng := rand.New(rand.NewSource(int64(randomSeed)))
		_, err := utils.RandomNat(prng, new(saferith.Nat).SetUint64(a), new(saferith.Nat).SetUint64(b))
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_NatSetBit(f *testing.F) {
	f.Fuzz(func(t *testing.T, a uint64, k int) {
		_, err := utils.NatSetBit(new(saferith.Nat).SetUint64(a), k-1)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

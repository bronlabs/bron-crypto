package signing

import (
	"crypto/sha256"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/trusteddealer"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestRedAlertProofsManual_Threshold2Of3(t *testing.T) {
	t.Parallel()

	t.Run("nonce", func(t *testing.T) {
		t.Parallel()
		testRedAlertProofsManual(t, newRedAlertNonce[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	})
	t.Run("chi", func(t *testing.T) {
		t.Parallel()
		testRedAlertProofsManual(t, newRedAlertChi[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	})
}

func testRedAlertProofsManual(
	t *testing.T,
	newParticipant func(*Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) *RedAlertParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar],
) {
	t.Helper()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	keyLen := 2048
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards, err := trusteddealer.Deal(curve, accessStructure, keyLen, prng)
	require.NoError(t, err)

	suite, err := sigecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from cggmp21 red alert")
	signingIDs := []sharing.ID{1, 2}
	signingQuorum := hashset.NewComparable(signingIDs...).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	cosigners := make(map[sharing.ID]*Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		cosigner, err := NewCosigner(ctxs[id], suite, shards[id], pcg.NewRandomised())
		require.NoError(t, err)
		cosigners[id] = cosigner
	}
	participants := slices.Collect(maps.Values(cosigners))

	r1bOut := make(map[sharing.ID]*Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*Round1P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for _, id := range signingIDs {
		r1bOut[id], r1uOut[id], err = cosigners[id].Round1()
		require.NoError(t, err)
	}

	r2bIn := ntu.MapBroadcastO2I(t, participants, r1bOut)
	r2uIn := ntu.MapUnicastO2I(t, participants, r1uOut)
	r2bOut := make(map[sharing.ID]*Round2Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*Round2P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *Cosigner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for _, id := range signingIDs {
		r2bOut[id], r2uOut[id], err = cosigners[id].Round2(r2bIn[id], r2uIn[id])
		require.NoError(t, err)
	}

	r3bIn := ntu.MapBroadcastO2I(t, participants, r2bOut)
	r3uIn := ntu.MapUnicastO2I(t, participants, r2uOut)
	r3bOut := make(map[sharing.ID]*Round3Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		r3bOut[id], err = cosigners[id].Round3(r3bIn[id], r3uIn[id])
		require.NoError(t, err)
	}

	r4bIn := ntu.MapBroadcastO2I(t, participants, r3bOut)
	for _, id := range signingIDs {
		_, redAlert, err := cosigners[id].Round4(r4bIn[id], message)
		require.NoError(t, err)
		require.Nil(t, redAlert)
		cosigners[id].state.round = 4
	}

	redAlerts := map[sharing.ID]*RedAlertParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{
		1: newParticipant(cosigners[1]),
		2: newParticipant(cosigners[2]),
	}
	redAlertParticipants := slices.Collect(maps.Values(redAlerts))
	redAlertOut := make(map[sharing.ID]*RedAlertBroadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		redAlertOut[id], err = redAlerts[id].Round1()
		require.NoError(t, err)
	}

	tampered := &RedAlertBroadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{
		BigD: cloneCiphertextMap(redAlertOut[1].BigD),
		BigF: cloneCiphertextMap(redAlertOut[1].BigF),
		Phi:  redAlertOut[1].Phi,
		PhiJ: maps.Clone(redAlertOut[1].PhiJ),
	}
	tampered.BigD[2], _, err = paillierEncryptInt(cosigners[2].shard.AuxInfo().PaillierSecretKey().Public(), num.Z().FromInt64(1), prng)
	require.NoError(t, err)
	require.ErrorContains(t, tampered.Validate(redAlerts[2], 1), "differs from round 2")

	redAlertIn := ntu.MapBroadcastO2I(t, redAlertParticipants, redAlertOut)
	for _, id := range signingIDs {
		require.NoError(t, redAlerts[id].Round2(redAlertIn[id]))
	}
}

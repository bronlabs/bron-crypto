package sign_bbot_test

import (
	"bytes"
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/signing/interactive/sign_bbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

// TODO: better tests
func Test_HappyPath(t *testing.T) {
	const THRESHOLD = 2
	prng := crand.Reader
	curve := p256.NewCurve()
	hashFunc := sha256.New
	shareholders := hashset.NewComparable(sharing.ID(1), sharing.ID(2), sharing.ID(3)).Freeze()
	quorum := hashset.NewComparable(sharing.ID(1), sharing.ID(2)).Freeze()

	shards, pk, err := trusted_dealer.DealRandom(curve, THRESHOLD, shareholders, prng)
	require.Equal(t, shards.Size(), shareholders.Size())
	require.NoError(t, err)
	publicKey := slices.Collect(maps.Values(maps.Collect(shards.Iter())))[0].PublicKey()

	var sessionId network.SID
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)
	suite := ecdsa.NewSuite(curve, hashFunc)
	transcript := hagrid.NewTranscript("test")
	c1Transcript := transcript.Clone()
	c2Transcript := transcript.Clone()

	cosigners := make([]*sign_bbot.Cosigner[*p256.Point, *p256.BaseFieldElement, *p256.Scalar], THRESHOLD)
	c1Shard, ok := shards.Get(sharing.ID(1))
	require.True(t, ok)
	c1, err := sign_bbot.NewCosigner(sessionId, sharing.ID(1), quorum, suite, c1Shard, prng, c1Transcript)
	require.NoError(t, err)
	c2Shard, ok := shards.Get(sharing.ID(2))
	require.True(t, ok)
	c2, err := sign_bbot.NewCosigner(sessionId, sharing.ID(2), quorum, suite, c2Shard, prng, c2Transcript)
	require.NoError(t, err)
	cosigners[0] = c1
	cosigners[1] = c2

	r1bo := make(map[sharing.ID]*sign_bbot.Round1Broadcast)
	r1uo := make(map[sharing.ID]ds.Map[sharing.ID, *sign_bbot.Round1P2P[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]])
	for _, cosigner := range cosigners {
		r1bo[cosigner.SharingID()], r1uo[cosigner.SharingID()], err = cosigner.Round1()
		require.NoError(t, err)

	}

	r2bi, r2ui := testutils.MapO2I(t, cosigners, r1bo, r1uo)
	r2bo := make(map[sharing.ID]*sign_bbot.Round2Broadcast[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
	r2uo := make(map[sharing.ID]ds.Map[sharing.ID, *sign_bbot.Round2P2P[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]])
	for _, cosigner := range cosigners {
		r2bo[cosigner.SharingID()], r2uo[cosigner.SharingID()], err = cosigner.Round2(r2bi[cosigner.SharingID()], r2ui[cosigner.SharingID()])
		require.NoError(t, err)
	}

	r3bi, r3ui := testutils.MapO2I(t, cosigners, r2bo, r2uo)
	r3bo := make(map[sharing.ID]*sign_bbot.Round3Broadcast[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
	r3uo := make(map[sharing.ID]ds.Map[sharing.ID, *sign_bbot.Round3P2P[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]])
	for _, cosigner := range cosigners {
		r3bo[cosigner.SharingID()], r3uo[cosigner.SharingID()], err = cosigner.Round3(r3bi[cosigner.SharingID()], r3ui[cosigner.SharingID()])
		require.NoError(t, err)
	}

	message := []byte("Hello World")
	r4bi, r4ui := testutils.MapO2I(t, cosigners, r3bo, r3uo)
	partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
	for _, cosigner := range cosigners {
		partialSignatures[cosigner.SharingID()], err = cosigner.Round4(r4bi[cosigner.SharingID()], r4ui[cosigner.SharingID()], message)
		require.NoError(t, err)
	}

	signature, err := dkls23.Aggregate(suite, publicKey, message, slices.Collect(maps.Values(partialSignatures))...)
	require.NoError(t, err)

	t.Run("signature is valid", func(t *testing.T) {
		nativePk := &nativeEcdsa.PublicKey{
			Curve: elliptic.P256(),
			// TODO: hope to return affine x and affine y
			X: pk.Coordinates().Value()[0].Cardinal().Big(),
			Y: pk.Coordinates().Value()[1].Cardinal().Big(),
		}

		digest, err := hashing.Hash(hashFunc, message)
		require.NoError(t, err)
		ok = nativeEcdsa.Verify(nativePk, digest, signature.R().Cardinal().Big(), signature.S().Cardinal().Big())
		require.True(t, ok)
	})

	t.Run("transcripts match", func(t *testing.T) {
		c1Bytes, err := c1Transcript.ExtractBytes("test", 32)
		require.NoError(t, err)
		c2Bytes, err := c2Transcript.ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(c1Bytes, c2Bytes))
	})
}

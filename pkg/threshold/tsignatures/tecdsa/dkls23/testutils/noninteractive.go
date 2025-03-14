package testutils

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	noninteractiveSigning "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/signing/noninteractive"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func MakePreGenParticipants(t *testing.T, sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls23.Shard, trans []transcripts.Transcript, prngs []io.Reader) []*noninteractiveSigning.PreGenParticipant {
	t.Helper()

	parties := make([]*noninteractiveSigning.PreGenParticipant, len(identities))
	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)
	preSigners := hashset.NewHashableHashSet(identities...)
	for i := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var tran transcripts.Transcript
		if len(trans) != 0 && trans[i] != nil {
			tran = trans[i]
		}

		parties[i], err = noninteractiveSigning.NewPreGenParticipant(sid, identities[i].(types.AuthKey), preSigners, shards[i], protocol, tran, prng, seededPrng)
		require.NoError(t, err)
	}

	return parties
}

func RunPreGen(t *testing.T, parties []*noninteractiveSigning.PreGenParticipant) []*dkls23.PreProcessingMaterial {
	var err error

	r1ob := make([]*signing.Round3Broadcast, len(parties))
	r1ou := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P], len(parties))
	for i := range parties {
		r1ob[i], r1ou[i], err = parties[i].Round1()
		require.NoError(t, err)
	}

	r2ib, r2iu := testutils.MapO2I(t, parties, r1ob, r1ou)
	r2ob := make([]*signing.Round4Broadcast, len(parties))
	r2ou := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P], len(parties))
	for i := range parties {
		r2ob[i], r2ou[i], err = parties[i].Round2(r2ib[i], r2iu[i])
		require.NoError(t, err)
	}

	r3ib, r3iu := testutils.MapO2I(t, parties, r2ob, r2ou)
	ppm := make([]*dkls23.PreProcessingMaterial, len(parties))
	for i := range parties {
		ppm[i], err = parties[i].Round3(r3ib[i], r3iu[i])
		require.NoError(t, err)
	}

	return ppm
}

func MakeNonInteractiveCosigners(t *testing.T, protocol types.ThresholdSignatureProtocol, quorum []types.IdentityKey, shards []*dkls23.Shard, preSignatures []*dkls23.PreProcessingMaterial) []*noninteractiveSigning.Cosigner {
	var err error

	cosigners := make([]*noninteractiveSigning.Cosigner, len(quorum))
	for i := range quorum {
		cosigners[i], err = noninteractiveSigning.NewCosigner(quorum[i].(types.AuthKey), shards[i], protocol, preSignatures[i])
		require.NoError(t, err)
	}

	return cosigners
}

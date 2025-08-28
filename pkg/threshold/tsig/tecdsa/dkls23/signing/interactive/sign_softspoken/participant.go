package sign_softspoken

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mul_softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN-"
	mulLabel        = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_MUL-"
	ckLabel         = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_CK-"
)

type Cosigner[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite     *ecdsa.Suite[P, B, S]
	sessionId network.SID
	sharingId sharing.ID
	shard     *tecdsa.Shard[P, B, S]
	quorum    network.Quorum
	prng      io.Reader
	tape      transcripts.Transcript
	state     CosignerState[P, B, S]
}

type CosignerState[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	zeroSampler *przs.Sampler[S]
	aliceMul    map[sharing.ID]*mul_softspoken.Alice[P, B, S]
	bobMul      map[sharing.ID]*mul_softspoken.Bob[P, B, S]

	round          network.Round
	ck             *hash_comm.Scheme
	r              S
	bigR           map[sharing.ID]P
	bigRCommitment map[sharing.ID]hash_comm.Commitment
	bigRWitness    hash_comm.Witness
	phi            S
	chi            map[sharing.ID]S
	c              map[sharing.ID][]S
	sk             S
	pk             map[sharing.ID]P
}

func NewCosigner[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, mySharingId sharing.ID, quorum network.Quorum, suite *ecdsa.Suite[P, B, S], shard *tecdsa.Shard[P, B, S], prng io.Reader, tape transcripts.Transcript) (*Cosigner[P, B, S], error) {
	if quorum == nil || suite == nil || shard == nil || prng == nil || tape == nil {
		return nil, errs.NewIsNil("argument")
	}
	if !quorum.Contains(mySharingId) {
		return nil, errs.NewValidation("sharing id not part of the quorum")
	}
	// TODO: should we directly take sharing id from the shard?
	if shard.Share().ID() != mySharingId {
		return nil, errs.NewValidation("sharing id does not match the shard id")
	}
	// TODO: check more matches quorum vs shard?

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	c := &Cosigner[P, B, S]{
		sharingId: mySharingId,
		shard:     shard,
		quorum:    quorum,
		suite:     suite,
		prng:      prng,
		tape:      tape,
	}

	c.state.aliceMul = make(map[sharing.ID]*mul_softspoken.Alice[P, B, S])
	c.state.bobMul = make(map[sharing.ID]*mul_softspoken.Bob[P, B, S])
	mulSuite, err := mul_softspoken.NewSuite(2, suite.Curve(), sha256.New)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create mul suite")
	}
	for id := range c.otherCosigners() {
		aliceSeed, ok := shard.OTReceiverSeeds().Get(id)
		if !ok {
			return nil, errs.NewFailed("couldn't find alice seed")
		}
		aliceTape := tape.Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.sharingId)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.state.aliceMul[id], err = mul_softspoken.NewAlice(c.sessionId, mulSuite, aliceSeed, prng, aliceTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise Alice")
		}

		bobSeed, ok := shard.OTSenderSeeds().Get(id)
		bobTape := tape.Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.sharingId)))
		c.state.bobMul[id], err = mul_softspoken.NewBob(c.sessionId, mulSuite, bobSeed, prng, bobTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise Bob")
		}
	}

	c.state.round = 1
	return c, nil
}

func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.sharingId
}

func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.quorum
}

func (c *Cosigner[P, B, S]) otherCosigners() iter.Seq[sharing.ID] {
	return func(yield func(id sharing.ID) bool) {
		for id := range c.quorum.Iter() {
			if id == c.sharingId {
				continue
			}
			if !yield(id) {
				return
			}
		}
	}
}

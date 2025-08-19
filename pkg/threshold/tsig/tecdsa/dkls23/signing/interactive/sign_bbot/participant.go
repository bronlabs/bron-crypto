package sign_bbot

import (
	"encoding/binary"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mul_bbot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TECDSA_DKLS23_BBOT-"
	mulLabel        = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_MUL-"
	ckLabel         = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_CK-"
)

//var (
//	_ types.ThresholdSignatureParticipant = (*Cosigner)(nil)
//)

type Cosigner[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Suite       *ecdsa.Suite[P, B, S]
	SessionId   network.SID
	MySharingId sharing.ID
	MyShard     *tecdsa.Shard[P, B, S]
	TheQuorum   network.Quorum
	Prng        io.Reader
	Tape        transcripts.Transcript
	State       CosignerState[P, B, S]
}

type CosignerState[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroSetup *przsSetup.Participant
	Zero      *przs.Sampler[S]
	AliceMul  map[sharing.ID]*mul_bbot.Alice[P, S]
	BobMul    map[sharing.ID]*mul_bbot.Bob[P, S]

	Round          network.Round
	Ck             *hash_comm.Scheme
	R              S
	BigR           map[sharing.ID]P
	BigRCommitment map[sharing.ID]hash_comm.Commitment
	BigRWitness    hash_comm.Witness
	Phi            S
	Chi            map[sharing.ID]S
	C              map[sharing.ID][]S
	Sk             S
	Pk             map[sharing.ID]P
}

func NewCosigner[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, mySharingId sharing.ID, quorum network.Quorum, suite *ecdsa.Suite[P, B, S], shard *tecdsa.Shard[P, B, S], prng io.Reader, tape transcripts.Transcript) (*Cosigner[P, B, S], error) {
	//	//if err := validateCosignerInputs(sessionId, authKey, protocol, shard, quorum); err != nil {
	//	//	return nil, errs.WrapValidation(err, "invalid inputs")
	//	//}
	//
	//	//sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	//	//sharingId, ok := sharingCfg.Reverse().Get(authKey)
	//	//if !ok {
	//	//	return nil, errs.NewFailed("couldn't find sharing identity in sharing config")
	//	}

	c := &Cosigner[P, B, S]{
		MySharingId: mySharingId,
		MyShard:     shard,
		TheQuorum:   quorum,
		Suite:       suite,
		Prng:        prng,
		Tape:        tape,
	}
	c.Tape.AppendBytes(transcriptLabel, sessionId[:])

	var err error
	c.State.ZeroSetup, err = przsSetup.NewParticipant(sessionId, mySharingId, quorum, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise zero setup protocol")
	}

	c.State.AliceMul = make(map[sharing.ID]*mul_bbot.Alice[P, S])
	c.State.BobMul = make(map[sharing.ID]*mul_bbot.Bob[P, S])
	for id := range c.otherCosigners() {
		aliceTape := tape.Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.MySharingId)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.State.AliceMul[id], err = mul_bbot.NewAlice(c.SessionId, c.Suite.Curve(), 2, prng, aliceTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise alice")
		}

		bobTape := tape.Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.MySharingId)))
		c.State.BobMul[id], err = mul_bbot.NewBob(c.SessionId, c.Suite.Curve(), 2, prng, bobTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise bob")
		}
	}

	c.State.Round = 1
	return c, nil
}

func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.MySharingId
}

func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.TheQuorum
}

func (c *Cosigner[P, B, S]) otherCosigners() iter.Seq[sharing.ID] {
	return func(yield func(id sharing.ID) bool) {
		for id := range c.TheQuorum.Iter() {
			if id == c.MySharingId {
				continue
			}
			if !yield(id) {
				return
			}
		}
	}
}

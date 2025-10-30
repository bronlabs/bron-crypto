package sign_bbot

import (
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
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/bbot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TECDSA_DKLS23_BBOT-"
	mulLabel        = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_MUL-"
	ckLabel         = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_CK-"
)

type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite     *ecdsa.Suite[P, B, S]
	sessionId network.SID
	shard     *dkls23.Shard[P, B, S]
	quorum    network.Quorum
	prng      io.Reader
	tape      transcripts.Transcript
	state     CosignerState[P, B, S]
}

type CosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	zeroSetup   *przsSetup.Participant
	zeroSampler *przs.Sampler[S]
	aliceMul    map[sharing.ID]*rvole_bbot.Alice[P, S]
	bobMul      map[sharing.ID]*rvole_bbot.Bob[P, S]

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

func NewCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, quorum network.Quorum, suite *ecdsa.Suite[P, B, S], shard *dkls23.Shard[P, B, S], prng io.Reader, tape transcripts.Transcript) (*Cosigner[P, B, S], error) {
	if quorum == nil || suite == nil || shard == nil || prng == nil || tape == nil {
		return nil, errs.NewIsNil("argument")
	}
	if suite.IsDeterministic() {
		return nil, errs.NewValidation("suite must be non-deterministic")
	}
	if !quorum.Contains(shard.Share().ID()) {
		return nil, errs.NewValidation("sharing id not part of the quorum")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	c := &Cosigner[P, B, S]{
		shard:  shard,
		quorum: quorum,
		suite:  suite,
		prng:   prng,
		tape:   tape,
	}

	var err error
	c.state.zeroSetup, err = przsSetup.NewParticipant(sessionId, shard.Share().ID(), quorum, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise zero setup protocol")
	}

	mulSuite, err := rvole_bbot.NewSuite(2, suite.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create mul suite")
	}
	c.state.aliceMul = make(map[sharing.ID]*rvole_bbot.Alice[P, S])
	c.state.bobMul = make(map[sharing.ID]*rvole_bbot.Bob[P, S])
	for id := range c.otherCosigners() {
		aliceTape := tape.Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.shard.Share().ID())), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.state.aliceMul[id], err = rvole_bbot.NewAlice(c.sessionId, mulSuite, prng, aliceTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise alice")
		}

		bobTape := tape.Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.shard.Share().ID())))
		c.state.bobMul[id], err = rvole_bbot.NewBob(c.sessionId, mulSuite, prng, bobTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise bob")
		}
	}

	c.state.round = 1
	return c, nil
}

func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.shard.Share().ID()
}

func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.quorum
}

func (c *Cosigner[P, B, S]) otherCosigners() iter.Seq[sharing.ID] {
	return func(yield func(id sharing.ID) bool) {
		for id := range c.quorum.Iter() {
			if id == c.shard.Share().ID() {
				continue
			}
			if !yield(id) {
				return
			}
		}
	}
}

package interactive

import (
	"fmt"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	bbotMul "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_bbot"
	zeroSample "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TECDSA_DKLS23_BBOT-"
	mulLabel        = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_MUL-"
	ckLabel         = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_CK-"
)

var (
	_ types.ThresholdSignatureParticipant = (*Cosigner)(nil)
)

type Cosigner struct {
	SessionId   []byte
	MyAuthKey   types.AuthKey
	MySharingId types.SharingID
	MyShard     *dkls23.Shard
	TheQuorum   ds.Set[types.IdentityKey]
	Protocol    types.ThresholdSignatureProtocol
	SharingCfg  types.SharingConfig
	Prng        io.Reader
	Tape        transcripts.Transcript
	State       CosignerState
}

type CosignerState struct {
	ZeroSetup *zeroSetup.Participant
	Zero      *zeroSample.Participant
	AliceMul  map[types.SharingID]*bbotMul.Alice
	BobMul    map[types.SharingID]*bbotMul.Bob

	Ck             *hash_comm.CommittingKey
	R              curves.Scalar
	BigR           map[types.SharingID]curves.Point
	BigRCommitment map[types.SharingID]hash_comm.Commitment
	BigRWitness    hash_comm.Witness
	Phi            curves.Scalar
	Chi            map[types.SharingID]curves.Scalar
	C              map[types.SharingID][]curves.Scalar
	Sk             curves.Scalar
	Pk             map[types.SharingID]curves.Point
}

func NewCosigner(sessionId []byte, authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader, tape transcripts.Transcript) (*Cosigner, error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	sharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("couldn't find sharing identity in sharing config")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	boundSessionId, err := tape.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	c := &Cosigner{
		SessionId:   boundSessionId,
		MyAuthKey:   authKey,
		MySharingId: sharingId,
		MyShard:     shard,
		TheQuorum:   quorum,
		Protocol:    protocol,
		SharingCfg:  sharingCfg,
		Prng:        prng,
		Tape:        tape,
	}

	zeroSetupProtocol, err := types.NewProtocol(protocol.Curve(), quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise zero setup protocol")
	}
	c.State.ZeroSetup, err = zeroSetup.NewParticipant(boundSessionId, authKey, zeroSetupProtocol, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise zero setup protocol")
	}

	c.State.AliceMul = make(map[types.SharingID]*bbotMul.Alice)
	c.State.BobMul = make(map[types.SharingID]*bbotMul.Bob)
	for id, key := range c.otherCosigners() {
		mulProtocol, err := types.NewProtocol(protocol.Curve(), hashset.NewHashableHashSet[types.IdentityKey](c.MyAuthKey, key))
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise mul protocol")
		}

		aliceTape := tape.Clone()
		aliceTape.AppendPoints(mulLabel, c.MyAuthKey.PublicKey(), key.PublicKey())
		c.State.AliceMul[id], err = bbotMul.NewAlice(authKey, mulProtocol, boundSessionId, 2, prng, aliceTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise alice")
		}

		bobTape := tape.Clone()
		bobTape.AppendPoints(mulLabel, key.PublicKey(), c.MyAuthKey.PublicKey())
		c.State.BobMul[id], err = bbotMul.NewBob(authKey, mulProtocol, boundSessionId, 2, prng, bobTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise bob")
		}
	}

	return c, nil
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.MyAuthKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.MySharingId
}

func (c *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return c.TheQuorum
}

func (c *Cosigner) otherCosigners() iter.Seq2[types.SharingID, types.IdentityKey] {
	return func(yield func(id types.SharingID, key types.IdentityKey) bool) {
		keyToId := c.SharingCfg.Reverse()
		for key := range c.TheQuorum.Iter() {
			if key.PublicKey().Equal(c.MyAuthKey.PublicKey()) {
				continue
			}
			id, ok := keyToId.Get(key)
			if !ok {
				panic("couldn't find identity in sharing config")
			}
			if !yield(id, key) {
				return
			}
		}
	}
}

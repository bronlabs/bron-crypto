package sign

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	baseOtMessageLength = 32

	transcriptLabel      = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN-"
	mulLabel             = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_MUL-"
	ckLabel              = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_CK-"
	przsRandomizerLabel  = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_PRZS_RANDOMIZER-"
	otRandomizerLabel    = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER-"
	otRandomizerSender   = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_SENDER-"
	otRandomizerReceiver = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_RECEIVER-"
	otRandomizerKey      = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_KEY-"
	ecbbotLabel          = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_BASE_OT-"
)

// Cosigner represents a signing participant.
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sessionID network.SID
	sharingID sharing.ID
	shard     *dkls23.Shard[P, B, S]
	zeroSeeds przs.Seeds
	quorum    network.Quorum
	suite     *ecdsa.Suite[P, B, S]
	tape      transcripts.Transcript
	prng      io.Reader

	baseOtSenders   map[sharing.ID]*ecbbot.Sender[P, S]
	baseOtReceivers map[sharing.ID]*ecbbot.Receiver[P, S]
	aliceMul        map[sharing.ID]*rvole_softspoken.Alice[P, B, S]
	bobMul          map[sharing.ID]*rvole_softspoken.Bob[P, B, S]
	zeroSampler     *przs.Sampler[S]

	state State[P, B, S]
}

// State tracks per-round signing state.
type State[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	baseOtReceiverOutputs map[sharing.ID]*vsot.ReceiverOutput
	baseOtSenderOutputs   map[sharing.ID]*vsot.SenderOutput

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

// NewCosigner returns a new cosigner.
func NewCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionID network.SID, quorum network.Quorum, suite *ecdsa.Suite[P, B, S], shard *dkls23.Shard[P, B, S], prng io.Reader, tape transcripts.Transcript) (*Cosigner[P, B, S], error) {
	if quorum == nil || suite == nil || shard == nil || prng == nil || tape == nil {
		return nil, ErrNil.WithMessage("argument")
	}
	if suite.IsDeterministic() {
		return nil, ErrValidation.WithMessage("suite must be non-deterministic")
	}
	if !quorum.Contains(shard.Share().ID()) {
		return nil, ErrValidation.WithMessage("sharing id not part of the quorum")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	zeroSeeds, err := randomizeZeroSeeds(shard.ZeroSeeds(), tape)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't randomise zero seeds")
	}

	otSuite, err := ecbbot.NewSuite(softspoken.Kappa, 1, suite.Curve())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("error creating vsot suite for participant")
	}
	otSenders := make(map[sharing.ID]*ecbbot.Sender[P, S])
	otReceivers := make(map[sharing.ID]*ecbbot.Receiver[P, S])
	sharingID := shard.Share().ID()
	for id := range quorum.Iter() {
		if id == sharingID {
			continue
		}

		otTape := tape.Clone()
		otTape.AppendBytes(ecbbotLabel, binary.LittleEndian.AppendUint64(nil, uint64(sharingID)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otSender, err := ecbbot.NewSender(sessionID, otSuite, otTape, prng)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("error creating bbot sender")
		}

		otTape = tape.Clone()
		otTape.AppendBytes(ecbbotLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(sharingID)))
		otReceiver, err := ecbbot.NewReceiver(sessionID, otSuite, otTape, prng)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("error creating bbot receiver")
		}

		otSenders[id] = otSender
		otReceivers[id] = otReceiver
	}

	//nolint:exhaustruct // lazy initialisation
	c := &Cosigner[P, B, S]{
		sessionID:       sessionID,
		sharingID:       sharingID,
		quorum:          quorum,
		shard:           shard,
		suite:           suite,
		zeroSeeds:       zeroSeeds,
		tape:            tape,
		prng:            prng,
		baseOtSenders:   otSenders,
		baseOtReceivers: otReceivers,
		aliceMul:        make(map[sharing.ID]*rvole_softspoken.Alice[P, B, S]),
		bobMul:          make(map[sharing.ID]*rvole_softspoken.Bob[P, B, S]),
		//nolint:exhaustruct // lazy initialisation
		state: State[P, B, S]{
			baseOtReceiverOutputs: make(map[sharing.ID]*vsot.ReceiverOutput),
			baseOtSenderOutputs:   make(map[sharing.ID]*vsot.SenderOutput),
			round:                 1,
		},
	}
	return c, nil
}

// SharingID returns the participant sharing identifier.
func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.shard.Share().ID()
}

// Quorum returns the protocol quorum.
func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.quorum
}

func randomizeZeroSeeds(seeds przs.Seeds, tape transcripts.Transcript) (przs.Seeds, error) {
	randomizerKey, err := tape.ExtractBytes(przsRandomizerLabel, (2*base.ComputationalSecurityBits+7)/8)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot extract randomizer")
	}

	randomizedSeeds := hashmap.NewComparable[sharing.ID, [przs.SeedLength]byte]()
	for id, seed := range seeds.Iter() {
		hasher, err := blake2b.New(przs.SeedLength, randomizerKey)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot create hasher")
		}
		_, err = hasher.Write(seed[:])
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot hash seed")
		}
		randomizedSeedBytes := hasher.Sum(nil)
		var randomizedSeed [przs.SeedLength]byte
		copy(randomizedSeed[:], randomizedSeedBytes)
		randomizedSeeds.Put(id, randomizedSeed)
	}
	return randomizedSeeds.Freeze(), nil
}

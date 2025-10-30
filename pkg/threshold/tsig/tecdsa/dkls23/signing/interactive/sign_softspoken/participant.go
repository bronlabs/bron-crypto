package sign_softspoken

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"iter"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel     = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN-"
	mulLabel            = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_MUL-"
	ckLabel             = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_CK-"
	przsRandomizerLabel = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_PRZS_RANDOMIZER-"
	otRandomizerLabel   = "BRON_CRYPTO_TECDSA_DKLS23_SOFTSPOKEN_OT_RANDOMIZER-"
)

type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite     *ecdsa.Suite[P, B, S]
	sessionId network.SID
	shard     *dkls23.Shard[P, B, S]
	zeroSeeds przs.Seeds
	quorum    network.Quorum
	prng      io.Reader
	tape      transcripts.Transcript
	state     CosignerState[P, B, S]
}

type CosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	zeroSampler *przs.Sampler[S]
	aliceMul    map[sharing.ID]*rvole_softspoken.Alice[P, B, S]
	bobMul      map[sharing.ID]*rvole_softspoken.Bob[P, B, S]

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
		return nil, errs.NewValidation("suite cannot be deterministic")
	}
	if !quorum.Contains(shard.Share().ID()) {
		return nil, errs.NewValidation("sharing id not part of the quorum")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	zeroSeeds, err := randomizeZeroSeeds(shard.ZeroSeeds(), tape)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't randomise zero seeds")
	}
	otSenderSeeds, otReceiverSeeds, err := randomizeOTSeeds(shard.OTSenderSeeds(), shard.OTReceiverSeeds(), tape)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't randomise OT seeds")
	}
	c := &Cosigner[P, B, S]{
		shard:     shard,
		zeroSeeds: zeroSeeds,
		quorum:    quorum,
		suite:     suite,
		prng:      prng,
		tape:      tape,
	}

	c.state.aliceMul = make(map[sharing.ID]*rvole_softspoken.Alice[P, B, S])
	c.state.bobMul = make(map[sharing.ID]*rvole_softspoken.Bob[P, B, S])
	mulSuite, err := rvole_softspoken.NewSuite(2, suite.Curve(), sha256.New)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create mul suite")
	}
	for id := range c.otherCosigners() {
		aliceSeed, ok := otReceiverSeeds.Get(id)
		if !ok {
			return nil, errs.NewFailed("couldn't find alice seed")
		}
		aliceTape := tape.Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.shard.Share().ID())), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.state.aliceMul[id], err = rvole_softspoken.NewAlice(c.sessionId, mulSuite, aliceSeed, prng, aliceTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise Alice")
		}

		bobSeed, ok := otSenderSeeds.Get(id)
		if !ok {
			return nil, errs.NewFailed("couldn't find bob seed")
		}
		bobTape := tape.Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.shard.Share().ID())))
		c.state.bobMul[id], err = rvole_softspoken.NewBob(c.sessionId, mulSuite, bobSeed, prng, bobTape)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't initialise Bob")
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

func randomizeZeroSeeds(seeds przs.Seeds, tape transcripts.Transcript) (przs.Seeds, error) {
	randomizerKey, err := tape.ExtractBytes(przsRandomizerLabel, (2*base.ComputationalSecurityBits+7)/8)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract randomizer")
	}

	randomizedSeeds := hashmap.NewComparable[sharing.ID, [przs.SeedLength]byte]()
	for id, seed := range seeds.Iter() {
		hasher, err := blake2b.New(przs.SeedLength, randomizerKey)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create hasher")
		}
		_, err = hasher.Write(seed[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot hash seed")
		}
		randomizedSeedBytes := hasher.Sum(nil)
		var randomizedSeed [przs.SeedLength]byte
		copy(randomizedSeed[:], randomizedSeedBytes)
		randomizedSeeds.Put(id, randomizedSeed)
	}
	return randomizedSeeds.Freeze(), nil
}

func randomizeOTSeeds(senderSeeds ds.Map[sharing.ID, *vsot.SenderOutput], receiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput], tape transcripts.Transcript) (ds.Map[sharing.ID, *vsot.SenderOutput], ds.Map[sharing.ID, *vsot.ReceiverOutput], error) {
	randomizerKey, err := tape.ExtractBytes(otRandomizerLabel, (2*base.ComputationalSecurityBits+7)/8)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot extract randomizer")
	}

	randomizedSenderSeeds := hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
	for id, seed := range senderSeeds.Iter() {
		randomizedSenderMessagePairs := make([][2][][]byte, seed.InferredXi())
		for xi := range seed.InferredXi() {
			randomizedSenderMessagePairs[xi][0] = make([][]byte, seed.InferredL())
			randomizedSenderMessagePairs[xi][1] = make([][]byte, seed.InferredL())
			for l := range seed.InferredL() {
				hasher, err := blake2b.New(len(seed.Messages[xi][0][l]), randomizerKey)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot create hasher")
				}
				_, err = hasher.Write(seed.Messages[xi][0][l])
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot hash seed")
				}
				randomizedSenderMessagePairs[xi][0][l] = hasher.Sum(nil)

				hasher, err = blake2b.New(len(seed.Messages[xi][1][l]), randomizerKey)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot create hasher")
				}
				_, err = hasher.Write(seed.Messages[xi][1][l])
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot hash seed")
				}
				randomizedSenderMessagePairs[xi][1][l] = hasher.Sum(nil)
			}
		}
		randomizedSenderSeeds.Put(id, &vsot.SenderOutput{
			SenderOutput: ot.SenderOutput[[]byte]{
				Messages: randomizedSenderMessagePairs,
			},
		})
	}

	randomizedReceiverSeeds := hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	for id, seed := range receiverSeeds.Iter() {
		randomizedReceiverMessages := make([][][]byte, seed.InferredXi())
		for xi := range seed.InferredXi() {
			randomizedReceiverMessages[xi] = make([][]byte, seed.InferredL())
			randomizedReceiverMessages[xi] = make([][]byte, seed.InferredL())
			for l := range seed.InferredL() {
				hasher, err := blake2b.New(len(seed.Messages[xi][l]), randomizerKey)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot create hasher")
				}
				_, err = hasher.Write(seed.Messages[xi][l])
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot hash seed")
				}
				randomizedReceiverMessages[xi][l] = hasher.Sum(nil)
			}
		}
		randomizedReceiverSeeds.Put(id, &vsot.ReceiverOutput{
			ReceiverOutput: ot.ReceiverOutput[[]byte]{
				Choices:  seed.Choices,
				Messages: randomizedReceiverMessages,
			},
		})
	}

	return randomizedSenderSeeds.Freeze(), randomizedReceiverSeeds.Freeze(), nil
}

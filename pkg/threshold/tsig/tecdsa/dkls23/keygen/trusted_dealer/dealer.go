package trusted_dealer

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
)

func DealRandom[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], threshold uint, shareholder ds.Set[sharing.ID], prng io.Reader) (ds.Map[sharing.ID, *dkls23.Shard[P, B, S]], *ecdsa.PublicKey[P, B, S], error) {
	generator := curve.Generator()
	feldmanDealer, err := feldman.NewScheme(generator, threshold, shareholder)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create shamir scheme")
	}

	feldmanOutput, secret, err := feldmanDealer.DealRandom(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal shares")
	}
	public := generator.ScalarMul(secret.Value())

	// create zero sharing seeds
	zeroSeeds := make(map[sharing.ID]ds.MutableMap[sharing.ID, [przs.SeedLength]byte])
	for id := range feldmanOutput.Shares().Iter() {
		zeroSeeds[id] = hashmap.NewComparable[sharing.ID, [przs.SeedLength]byte]()
	}
	for me := range feldmanOutput.Shares().Iter() {
		for they := range feldmanOutput.Shares().Iter() {
			if me >= they {
				continue
			}
			var seed [przs.SeedLength]byte
			if _, err = io.ReadFull(prng, seed[:]); err != nil {
				return nil, nil, errs.WrapRandomSample(err, "cannot sample seed")
			}
			zeroSeeds[me].Put(they, seed)
			zeroSeeds[they].Put(me, seed)
		}
	}

	// create OT seeds
	senderSeeds := make(map[sharing.ID]ds.MutableMap[sharing.ID, *vsot.SenderOutput])
	receiverSeeds := make(map[sharing.ID]ds.MutableMap[sharing.ID, *vsot.ReceiverOutput])
	for id := range feldmanOutput.Shares().Iter() {
		senderSeeds[id] = hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
		receiverSeeds[id] = hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	}
	for me := range feldmanOutput.Shares().Iter() {
		for they := range feldmanOutput.Shares().Iter() {
			if me == they {
				continue
			}

			choices := make([]byte, softspoken.Kappa/8)
			if _, err := io.ReadFull(prng, choices); err != nil {
				return nil, nil, errs.WrapRandomSample(err, "cannot sample choices")
			}
			sender := &vsot.SenderOutput{
				SenderOutput: ot.SenderOutput[[]byte]{
					Messages: make([][2][][]byte, softspoken.Kappa),
				},
			}
			receiver := &vsot.ReceiverOutput{
				ReceiverOutput: ot.ReceiverOutput[[]byte]{
					Choices:  choices,
					Messages: make([][][]byte, softspoken.Kappa),
				},
			}
			for kappa := range softspoken.Kappa {
				m0 := make([]byte, 32)
				if _, err := io.ReadFull(prng, m0); err != nil {
					return nil, nil, errs.WrapRandomSample(err, "cannot sample m0")
				}
				m1 := make([]byte, 32)
				if _, err := io.ReadFull(prng, m1); err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot sample m1")
				}
				c := (choices[kappa/8] >> (kappa % 8)) & 0b1
				sender.Messages[kappa][0] = [][]byte{m0}
				sender.Messages[kappa][1] = [][]byte{m1}
				receiver.Messages[kappa] = sender.Messages[kappa][c]
			}

			senderSeeds[me].Put(they, sender)
			receiverSeeds[they].Put(me, receiver)
		}
	}

	publicKey, err := ecdsa.NewPublicKey(public)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "invalid public key")
	}
	result := hashmap.NewComparable[sharing.ID, *dkls23.Shard[P, B, S]]()
	for id, feldmanShare := range feldmanOutput.Shares().Iter() {
		shard := dkls23.NewShard(feldmanShare, feldmanDealer.AccessStructure(), publicKey, zeroSeeds[id].Freeze(), senderSeeds[id].Freeze(), receiverSeeds[id].Freeze())
		result.Put(id, shard)
	}

	return result.Freeze(), publicKey, nil
}

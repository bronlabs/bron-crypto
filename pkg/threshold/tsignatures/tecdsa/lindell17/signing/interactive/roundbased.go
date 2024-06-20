package interactive_signing

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

func sendTo[M any](p2p chan<- ds.Map[types.IdentityKey, M], destination types.IdentityKey, m M) {
	p2pMessage := hashmap.NewHashableHashMap[types.IdentityKey, M]()
	p2pMessage.Put(destination, m)
	p2p <- p2pMessage
}

func receiveFrom[M any](p2p <-chan ds.Map[types.IdentityKey, M], source types.IdentityKey) (M, error) {
	p2pMessage := <-p2p
	m, ok := p2pMessage.Get(source)
	if !ok {
		return *new(M), errs.NewFailed("no message")
	}
	return m, nil
}

func PrimaryRunner(router roundbased.MessageRouter, participant *PrimaryCosigner, message []byte) (*ecdsa.Signature, error) {
	me := participant.IdentityKey()
	him := participant.secondaryIdentityKey
	r1 := roundbased.NewUnicastRound[*Round1OutputP2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2OutputP2P](me, 2, router)
	r3 := roundbased.NewUnicastRound[*Round3OutputP2P](me, 3, router)
	r4 := roundbased.NewUnicastRound[*lindell17.PartialSignature](me, 4, router)

	// round 1
	r1Out, err := participant.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	sendTo(r1.UnicastOut(), him, r1Out)

	// round 3
	r3In, err := receiveFrom(r2.UnicastIn(), him)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 3 failed")
	}
	r3Out, err := participant.Round3(r3In)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 3 failed")
	}
	sendTo(r3.UnicastOut(), him, r3Out)

	// round 5
	r5In, err := receiveFrom(r4.UnicastIn(), him)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 5 failed")
	}
	r5Out, err := participant.Round5(r5In, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 5 failed")
	}

	return r5Out, nil
}

func SecondaryRunner(router roundbased.MessageRouter, participant *SecondaryCosigner, message []byte) error {
	me := participant.IdentityKey()
	her := participant.primaryIdentityKey
	r1 := roundbased.NewUnicastRound[*Round1OutputP2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2OutputP2P](me, 2, router)
	r3 := roundbased.NewUnicastRound[*Round3OutputP2P](me, 3, router)
	r4 := roundbased.NewUnicastRound[*lindell17.PartialSignature](me, 4, router)

	// round 2
	r2In, err := receiveFrom(r1.UnicastIn(), her)
	if err != nil {
		return errs.WrapFailed(err, "round 2 failed")
	}
	r2Out, err := participant.Round2(r2In)
	if err != nil {
		return errs.WrapFailed(err, "round 2 failed")
	}
	sendTo(r2.UnicastOut(), her, r2Out)

	// round 4
	r4In, err := receiveFrom(r3.UnicastIn(), her)
	if err != nil {
		return errs.WrapFailed(err, "round 4 failed")
	}
	r4Out, err := participant.Round4(r4In, message)
	if err != nil {
		return errs.WrapFailed(err, "round 4 failed")
	}
	sendTo(r4.UnicastOut(), her, r4Out)

	return nil
}

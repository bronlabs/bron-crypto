package interactive

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// import (
//
//	"iter"
//
//	"github.com/bronlabs/bron-crypto/pkg/base/curves"
//	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
//	"github.com/bronlabs/bron-crypto/pkg/base/errs"
//	"github.com/bronlabs/bron-crypto/pkg/base/types"
//	"github.com/bronlabs/bron-crypto/pkg/hashing"
//	"github.com/bronlabs/bron-crypto/pkg/network"
//	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
//	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
//
// )
//
//	func validateCosignerInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls23.Shard, quorum ds.Set[types.IdentityKey]) error {
//		if len(sessionId) == 0 {
//			return errs.NewLength("invalid session id: %s", sessionId)
//		}
//		if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
//			return errs.WrapValidation(err, "threshold signature protocol config")
//		}
//		if err := types.ValidateAuthKey(authKey); err != nil {
//			return errs.WrapValidation(err, "auth key")
//		}
//		if err := shard.Validate(protocol); err != nil {
//			return errs.WrapValidation(err, "could not validate shard")
//		}
//		if quorum == nil {
//			return errs.NewIsNil("invalid number of session participants")
//		}
//		if quorum.Size() < int(protocol.Threshold()) {
//			return errs.NewSize("not enough session participants: %d", quorum.Size())
//		}
//		if quorum.Difference(protocol.Participants()).Size() != 0 {
//			return errs.NewMembership("there are some present session participant that are not part of the protocol config")
//		}
//		if !quorum.Contains(authKey) {
//			return errs.NewMembership("session participants do not include me")
//		}
//
//		return nil
//	}
//
//	func messageToScalar(c *Cosigner, message []byte) (curves.Scalar, error) {
//		messageHash, err := hashing.Hash(c.Protocol.SigningSuite().Hash(), message)
//		if err != nil {
//			return nil, errs.WrapHashing(err, "cannot hash message")
//		}
//		mPrimeUint := ecdsa.BitsToInt(messageHash, c.Protocol.Curve())
//		mPrime, err := c.Protocol.Curve().ScalarField().Element().SetBytes(mPrimeUint.Bytes())
//		if err != nil {
//			return nil, errs.WrapSerialisation(err, "cannot convert message to scalar")
//		}
//		return mPrime, nil
//	}
//
//	type party struct {
//		id  types.SharingID
//		key types.IdentityKey
//	}
type message[B network.Message, U network.Message] struct {
	broadcast B
	p2p       U
}

func validateIncomingMessages[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S], MB network.Message, MU network.Message](c *Cosigner[P, B, S], rIn network.Round, bIn network.RoundMessages[MB], uIn network.RoundMessages[MU]) (iter.Seq2[sharing.ID, message[MB, MU]], error) {
	if rIn != c.State.Round {
		return nil, errs.NewFailed("invalid round")
	}
	//if err := network.ValidateMessages(c.Protocol, c.TheQuorum, c.MyAuthKey, bIn); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid broadcast input")
	//}
	//if err := network.ValidateMessages(c.Protocol, c.TheQuorum, c.MyAuthKey, uIn); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid p2p input")
	//}

	return func(yield func(p sharing.ID, m message[MB, MU]) bool) {
		for id := range c.TheQuorum.Iter() {
			if id == c.MySharingId {
				continue
			}

			b, ok := bIn.Get(id)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			u, ok := uIn.Get(id)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			if !yield(id, message[MB, MU]{broadcast: b, p2p: u}) {
				return
			}
		}
	}, nil
}

type messagePointerConstraint[MP network.Message, M any] interface {
	*M
	network.Message
}

func outgoingP2PMessages[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S], UPtr messagePointerConstraint[UPtr, U], U any](c *Cosigner[P, B, S], uOut ds.MutableMap[sharing.ID, UPtr]) iter.Seq2[sharing.ID, UPtr] {
	return func(yield func(p sharing.ID, out UPtr) bool) {
		for id := range c.TheQuorum.Iter() {
			if id == c.MySharingId {
				continue
			}

			u := new(U)
			if !yield(id, UPtr(u)) {
				return
			}
			uOut.Put(id, UPtr(u))
		}
	}
}

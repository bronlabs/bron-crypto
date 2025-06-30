package interactive

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func validateCosignerInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls23.Shard, quorum ds.Set[types.IdentityKey]) error {
	if len(sessionId) == 0 {
		return errs.NewLength("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate shard")
	}
	if quorum == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if quorum.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", quorum.Size())
	}
	if quorum.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !quorum.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}

	return nil
}

func messageToScalar(c *Cosigner, message []byte) (curves.Scalar, error) {
	messageHash, err := hashing.Hash(c.Protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	mPrimeUint := ecdsa.BitsToInt(messageHash, c.Protocol.Curve())
	mPrime, err := c.Protocol.Curve().ScalarField().Element().SetBytes(mPrimeUint.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot convert message to scalar")
	}
	return mPrime, nil
}

type party struct {
	id  types.SharingID
	key types.IdentityKey
}

type message[B network.Message[types.ThresholdSignatureProtocol], U network.Message[types.ThresholdSignatureProtocol]] struct {
	broadcast B
	p2p       U
}

func validateIncomingMessages[B network.Message[types.ThresholdSignatureProtocol], U network.Message[types.ThresholdSignatureProtocol]](c *Cosigner, rIn int, bIn network.RoundMessages[types.ThresholdSignatureProtocol, B], uIn network.RoundMessages[types.ThresholdSignatureProtocol, U]) (iter.Seq2[party, message[B, U]], error) {
	if rIn != c.State.Round {
		return nil, errs.NewFailed("invalid round")
	}
	if err := network.ValidateMessages(c.Protocol, c.TheQuorum, c.MyAuthKey, bIn); err != nil {
		return nil, errs.WrapFailed(err, "invalid broadcast input")
	}
	if err := network.ValidateMessages(c.Protocol, c.TheQuorum, c.MyAuthKey, uIn); err != nil {
		return nil, errs.WrapFailed(err, "invalid p2p input")
	}

	return func(yield func(p party, m message[B, U]) bool) {
		keyToId := c.SharingCfg.Reverse()
		for key := range c.TheQuorum.Iter() {
			if key.PublicKey().Equal(c.MyAuthKey.PublicKey()) {
				continue
			}
			id, ok := keyToId.Get(key)
			if !ok {
				panic("this should never happen: couldn't find identity in sharing config")
			}
			b, ok := bIn.Get(key)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			u, ok := uIn.Get(key)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			if !yield(party{id: id, key: key}, message[B, U]{broadcast: b, p2p: u}) {
				return
			}
		}
	}, nil
}

type messagePointerConstraint[MP network.Message[types.ThresholdSignatureProtocol], M any] interface {
	*M
	network.Message[types.ThresholdSignatureProtocol]
}

func outgoingP2PMessages[UPtr messagePointerConstraint[UPtr, U], U any](c *Cosigner, uOut network.RoundMessages[types.ThresholdSignatureProtocol, UPtr]) iter.Seq2[party, UPtr] {
	return func(yield func(p party, out UPtr) bool) {
		keyToId := c.SharingCfg.Reverse()
		for key := range c.TheQuorum.Iter() {
			if key.PublicKey().Equal(c.MyAuthKey.PublicKey()) {
				continue
			}
			id, ok := keyToId.Get(key)
			if !ok {
				panic("this should never happen: couldn't find identity in sharing config")
			}

			u := new(U)
			if !yield(party{id: id, key: key}, UPtr(u)) {
				return
			}
			uOut.Put(key, UPtr(u))
		}
	}
}

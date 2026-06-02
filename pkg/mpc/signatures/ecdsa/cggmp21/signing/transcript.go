package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

const (
	round1BroadcastTranscriptLabel = "CGGMP21SignRound1Broadcast"
	round2BroadcastTranscriptLabel = "CGGMP21SignRound2Broadcast"
	round3BroadcastTranscriptLabel = "CGGMP21SignRound3Broadcast"
)

func collectAndAppendBroadcastMessages[
	P curves.Point[P, B, S],
	B algebra.PrimeFieldElement[B],
	S algebra.PrimeFieldElement[S],
	M network.Message[*Signer[P, B, S]],
](
	signer *Signer[P, B, S],
	label string,
	local M,
	incoming network.RoundMessages[M, *Signer[P, B, S]],
) (map[sharing.ID]M, error) {
	messages := make(map[sharing.ID]M)
	messages[signer.ctx.HolderID()] = local
	for id := range signer.ctx.OtherPartiesOrdered() {
		message, ok := incoming.Get(id)
		if !ok {
			return nil, network.ErrMissing.WithMessage("broadcast from %d", id)
		}
		messages[id] = message
	}

	for id := range signer.ctx.AllPartiesOrdered() {
		message, ok := messages[id]
		if !ok || utils.IsNil(message) {
			return nil, cggmp21.ErrNil.WithMessage("broadcast message from %d", id)
		}
		data, err := serde.MarshalCBOR(message)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot serialise broadcast message from %d", id)
		}
		signer.ctx.Transcript().AppendBytes(label, id.Bytes(), data)
	}
	return messages, nil
}

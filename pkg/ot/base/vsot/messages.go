package vsot

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.MessageLike = (*Round1P2P)(nil)
var _ network.MessageLike = (*Round2P2P)(nil)
var _ network.MessageLike = (*Round3P2P)(nil)
var _ network.MessageLike = (*Round4P2P)(nil)
var _ network.MessageLike = (*Round5P2P)(nil)

type (
	Round1P2P struct {
		Proof     compiler.NIZKPoKProof
		PublicKey curves.Point

		_ ds.Incomparable
	}
	Round2P2P struct {
		MaskedChoices [][]ot.ChoiceBits
	}
	Round3P2P struct {
		Challenge []ot.Message
	}
	Round4P2P struct {
		Responses []ot.Message
	}
	Round5P2P struct {
		Openings []ot.MessagePair
	}
)

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if r1p2p.Proof == nil {
		return errs.NewIsNil("proof")
	}
	if r1p2p.PublicKey == nil {
		return errs.NewIsNil("public key")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	if len(r2p2p.MaskedChoices) != Xi {
		return errs.NewSize("len(MaskedChoices):%d  !=  Xi:%d", len(r2p2p.MaskedChoices), Xi)
	}
	for i, maskedChoice := range r2p2p.MaskedChoices {
		if len(maskedChoice) != L {
			return errs.NewSize("len(MaskedChoices[%d]):%d  !=  L:%d", i, len(maskedChoice), L)
		}
	}
	return nil
}

func (r3p2p *Round3P2P) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	if len(r3p2p.Challenge) != Xi {
		return errs.NewSize("len(Challenge):%d  !=  Xi:%d", len(r3p2p.Challenge), Xi)
	}
	for i, challenge := range r3p2p.Challenge {
		if len(challenge) != L {
			return errs.NewSize("len(Challenge[%d]):%d  !=  L:%d", i, len(challenge), L)
		}
	}
	return nil
}

func (r4p2p *Round4P2P) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	if len(r4p2p.Responses) != Xi {
		return errs.NewSize("len(Responses):%d  !=  Xi:%d", len(r4p2p.Responses), Xi)
	}
	for i, response := range r4p2p.Responses {
		if len(response) != L {
			return errs.NewSize("len(Responses[%d]):%d  !=  L:%d", i, len(response), L)
		}
	}
	return nil
}

func (r5p2p *Round5P2P) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	if len(r5p2p.Openings) != Xi {
		return errs.NewSize("len(Openings):%d  !=  Xi:%d", len(r5p2p.Openings), Xi)
	}
	for i, opening := range r5p2p.Openings {
		if len(opening[0]) != L {
			return errs.NewSize("len(Openings[%d][0]):%d  !=  L:%d", i, len(opening[0]), L)
		}
		if len(opening[1]) != L {
			return errs.NewSize("len(Openings[%d][1]):%d  !=  L:%d", i, len(opening[1]), L)
		}
	}
	return nil
}

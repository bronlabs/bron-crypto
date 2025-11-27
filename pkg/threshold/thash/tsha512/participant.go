package tsha512

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Participant struct {
	id     sharing.ID
	quorum network.Quorum
	prng   io.Reader
}

func NewParticipant(id sharing.ID, quorum network.Quorum, prng io.Reader) (*Participant, error) {
	if quorum == nil || !quorum.Contains(id) || quorum.Size() != 3 {
		return nil, errs.NewValidation("invalid arguments")
	}

	return &Participant{id: id, quorum: quorum, prng: prng}, nil
}

func (p *Participant) ID() sharing.ID {
	return p.id
}

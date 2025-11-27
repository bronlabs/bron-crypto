package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Participant struct {
	sid       network.SID
	sharingId sharing.ID
	quorum    network.Quorum
	prng      io.Reader
}

func NewParticipant(sid network.SID, sharingId sharing.ID, quorum network.Quorum, prng io.Reader) (*Participant, error) {
	if quorum == nil || !quorum.Contains(sharingId) || quorum.Size() != 3 || prng == nil {
		return nil, errs.NewFailed("invalid arguments")
	}

	p := &Participant{sid, sharingId, quorum, prng}
	return p, nil
}

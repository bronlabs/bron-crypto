package redistribute

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Option configures an optional behaviour of a redistribution participant.
type Option func(p optionalTrustedAnchorIDReceiver) error

// WithTrustedAnchorID configures the previous shareholder whose round-2
// metadata is used as the reference for identifiable-abort checks.
func WithTrustedAnchorID(trustedAnchorID sharing.ID) Option {
	return func(p optionalTrustedAnchorIDReceiver) error {
		if err := p.setTrustedAnchorID(trustedAnchorID); err != nil {
			return errs.Wrap(err).WithMessage("cannot set trusted anchor ID")
		}
		return nil
	}
}

type optionalTrustedAnchorIDReceiver interface {
	setTrustedAnchorID(trustedAnchorID sharing.ID) error
}

func (p *Participant[G, S]) setTrustedAnchorID(trustedAnchorID sharing.ID) error {
	if p.trustedAnchorID != 0 {
		return ErrInvalidArgument.WithMessage("trusted anchor ID already set")
	}
	if !p.prevShareholders.Contains(trustedAnchorID) {
		return ErrInvalidArgument.WithMessage("trusted anchor ID not in previous shareholders")
	}
	p.trustedAnchorID = trustedAnchorID
	return nil
}

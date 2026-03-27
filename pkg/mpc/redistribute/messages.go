package redistribute

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// Round1Broadcast carries the public commitments that let recoverees verify
// the redistributed subshares.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// ShareVerificationVector authenticates the recoverer's previous share.
	ShareVerificationVector *feldman.VerificationVector[G, S]
	// SubShareVerificationVector authenticates the recoverer's redistributed
	// contribution under the next access structure.
	SubShareVerificationVector *feldman.VerificationVector[G, S]
}

// Validate checks that the broadcast contains well-formed verification data.
func (m *Round1Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil || m.ShareVerificationVector == nil || m.SubShareVerificationVector == nil {
		return ErrValidation.WithMessage("invalid arguments")
	}
	if !m.ShareVerificationVector.Value().IsColumnVector() {
		return ErrValidation.WithMessage("invalid share verification vector")
	}
	if !m.SubShareVerificationVector.Value().IsColumnVector() {
		return ErrValidation.WithMessage("invalid sub-share verification vector")
	}

	return nil
}

// Round1P2P carries one recoverer's private subshare for a specific recoveree.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// SubShare is the recoverer's private contribution to the recipient's new share.
	SubShare *kw.Share[S]
}

// Validate checks that the private redistribution message is well formed.
func (m *Round1P2P[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil || m.SubShare == nil {
		return ErrValidation.WithMessage("invalid arguments")
	}

	return nil
}

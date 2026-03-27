package redistribute

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ShareVerificationVector    *feldman.VerificationVector[G, S]
	SubShareVerificationVector *feldman.VerificationVector[G, S]
}

func (*Round1Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	// TODO: implement
	return nil
}

type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	SubShare *kw.Share[S]
}

func (*Round1P2P[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	// TODO: implement
	return nil
}

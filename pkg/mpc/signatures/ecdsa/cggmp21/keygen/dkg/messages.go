package dkg

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/canetti"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/errs-go/errs"
)

type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Canetti *canetti.Round1Broadcast[P, S]
	V       hashcom.Commitment
}

func (m *Round1Broadcast[P, B, S]) Validate(p *Participant[P, B, S], senderID sharing.ID) error {
	if m == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil message")
	}
	if err := m.Canetti.Validate(p.canettiParticipant, senderID); err != nil {
		return errs.Wrap(err).WithMessage("invalid canetti round 1 broadcast")
	}
	return nil
}

type CommitmentMessage[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	SessionID network.SID
	SharingID sharing.ID
	X         map[sharing.ID]P
	Y         map[sharing.ID]*dhc.PublicKey[P, B, S]
	N         *num.NatPlus
	NHat      *num.NatPlus
	s         *znstar.RSAGroupElementUnknownOrder
	t         *znstar.RSAGroupElementUnknownOrder
	psi       compiler.NIZKPoKProof
	rid       []byte
}

func (m *CommitmentMessage[P, B, S]) Bytes() []byte {
	var data []byte
	data = append(data, m.SessionID[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.SharingID))
	for _, xi := range maputils.SortedValues(m.X) {
		data = append(data, xi.ToCompressed()...)
	}
	for _, yi := range maputils.SortedValues(m.Y) {
		data = append(data, yi.Value().ToCompressed()...)
	}
	data = append(data, m.N.BytesBE()...)
	data = append(data, m.NHat.BytesBE()...)
	data = append(data, m.s.Value().BytesBE()...)
	data = append(data, m.t.Value().BytesBE()...)
	data = append(data, m.psi...)
	data = append(data, m.rid...)
	return data
}

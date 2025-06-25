package ecbbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

var _ network.Message[types.Protocol] = (*Round1P2P)(nil)
var _ network.Message[types.Protocol] = (*Round2P2P)(nil)

type Round1P2P struct {
	MS curves.Point // mS ∈ Point
}

type Round2P2P struct {
	Phi [][2][]curves.Point // Φ ∈ [ξ][2][L]Point
}

func (r1p2p *Round1P2P) Validate(protocol types.Protocol) error {
	if r1p2p.MS == nil {
		return errs.NewIsNil("mS")
	}
	if r1p2p.MS.Curve() != protocol.Curve() {
		return errs.NewCurve("mS curve %s is not protocol curve %s", r1p2p.MS.Curve().Name(), protocol.Curve().Name())
	}
	if r1p2p.MS.IsAdditiveIdentity() {
		return errs.NewIsNil("mS is identity")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol types.Protocol) error {
	otProtocol, ok := protocol.(*ot.Protocol)
	if !ok {
		return errs.NewArgument("protocol is not ot.Protocol")
	}
	L, Xi := otProtocol.L, otProtocol.Xi
	if len(r2p2p.Phi) == 0 {
		return errs.NewIsNil("phi")
	}
	if len(r2p2p.Phi) != Xi {
		return errs.NewLength("len(phi)=%d is not Xi=%d", len(r2p2p.Phi), Xi)
	}
	for i := 0; i < Xi; i++ {
		for j := 0; j < 2; j++ {
			if len(r2p2p.Phi[i][j]) != L {
				return errs.NewLength("len(phi[%d][%d])=%d is not L=%d", i, j, len(r2p2p.Phi[i][j]), L)
			}
			for l := 0; l < L; l++ {
				if r2p2p.Phi[i][j][l] == nil {
					return errs.NewIsNil("phi[%d][%d][%d]", i, j, l)
				}
				if r2p2p.Phi[i][j][l].Curve() != otProtocol.Curve() {
					return errs.NewCurve("phi[%d][%d][%d] curve %s is not protocol curve %s", i, j, l, r2p2p.Phi[i][j][l].Curve().Name(), otProtocol.Curve().Name())
				}
				if r2p2p.Phi[i][j][l].IsAdditiveIdentity() {
					return errs.NewIsNil("phi[%d][%d][%d] is identity", i, j, l)
				}
			}
		}
	}
	return nil
}

type ReceiverOutput struct {
	Choices ot.PackedBits
	R       [][]curves.Scalar
}

func NewReceiverOutput(chi, l int) *ReceiverOutput {
	r := make([][]curves.Scalar, chi)
	for i := range r {
		r[i] = make([]curves.Scalar, l)
	}
	return &ReceiverOutput{R: r}
}

type SenderOutput struct {
	S [][2][]curves.Scalar
}

func NewSenderOutput(chi, l int) *SenderOutput {
	s := make([][2][]curves.Scalar, chi)
	for i := range s {
		s[i][0] = make([]curves.Scalar, l)
		s[i][1] = make([]curves.Scalar, l)
	}
	return &SenderOutput{S: s}
}

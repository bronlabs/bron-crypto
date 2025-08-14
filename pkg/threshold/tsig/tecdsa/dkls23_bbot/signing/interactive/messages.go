package interactive

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mul_bbot"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
)

// import (
//
//	"github.com/bronlabs/bron-crypto/pkg/base/curves"
//	"github.com/bronlabs/bron-crypto/pkg/base/errs"
//	"github.com/bronlabs/bron-crypto/pkg/base/types"
//	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
//	"github.com/bronlabs/bron-crypto/pkg/network"
//	bbotMul "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_bbot"
//	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
//
// )
//
// var (
//
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round1P2P)(nil)
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2P2P)(nil)
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round3Broadcast)(nil)
//	_ network.Message[types.ThresholdSignatureProtocol] = (*Round3P2P)(nil)
//
// )
type Round1Broadcast struct {
	ZeroSetupR1    *przsSetup.Round1Broadcast
	BigRCommitment hash_comm.Commitment
}

func (m *Round1Broadcast) Bytes() []byte {
	panic("not implemented")
}

type Round1P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR1 *mul_bbot.Round1P2P[P, S]
}

func (m *Round1P2P[P, B, S]) Bytes() []byte {
	panic("not implemented")
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P
	BigRWitness hash_comm.Witness
}

func (m *Round2Broadcast[P, B, S]) Bytes() []byte {
	panic("not implemented")
}

type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroSetupR2 *przsSetup.Round2P2P
	MulR2       *mul_bbot.Round2P2P[P, S]
}

func (m *Round2P2P[P, B, S]) Bytes() []byte {
	panic("not implemented")
}

type Round3Broadcast[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Pk P
}

func (m *Round3Broadcast[P, B, S]) Bytes() []byte {
	panic("not implemented")
}

type Round3P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR3 *mul_bbot.Round3P2P[S]

	GammaU P
	GammaV P
	Psi    S
}

func (m *Round3P2P[P, B, S]) Bytes() []byte {
	panic("not implemented")
}

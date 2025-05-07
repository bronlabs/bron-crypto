package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	pedersen_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
)

type Round1Broadcast[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	PedersenVerification []*pedersen_comm.Commitment[P, F, S]
}

//func (m *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
//	if len(m.PedersenVerification) != int(protocol.Threshold()) {
//		return errs.NewValidation("invalid vector length")
//	}
//
//	return nil
//}

type Round2P2P[S fields.PrimeFieldElement[S]] struct {
	PedersenShare *pedersen_vss.Share[S]
}

//func (m *Round2P2P) Validate(protocol types.ThresholdProtocol) error {
//	if m.PedersenShare == nil || m.PedersenShare.SharingId() < 1 || uint(m.PedersenShare.SharingId()) > protocol.TotalParties() {
//		return errs.NewValidation("invalid pedersen share")
//	}
//
//	return nil
//}

type Round2Broadcast[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	FeldmanVerification []P
}

//func (m *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
//	if len(m.FeldmanVerification) != int(protocol.Threshold()) {
//		return errs.NewValidation("invalid vector length")
//	}
//
//	return nil
//}

package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

const FreeCoefficientCanBeIdentity types.ValidationFlag = "FREE_COEFFICIENT_IDENTITY"

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)

type Round1Broadcast struct {
	Ci        []curves.Point
	DlogProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round1P2P struct {
	Xij curves.Scalar

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(r1b.Ci) == 0 {
		return errs.NewSize("ci is empty")
	}
	if len(r1b.Ci) != int(protocol.Threshold()) {
		return errs.NewLength("len(ci) == %d != t == %d", len(r1b.Ci), protocol.Threshold())
	}
	// ci[0] is allowed to be identity in some protocols, e.g., in recovery/refresh
	freeCoefficientCanBeIdentity := protocol.Flags().Contains(FreeCoefficientCanBeIdentity)
	for i, c := range r1b.Ci {
		if c == nil {
			return errs.NewIsNil("ci[%d]", i)
		}
		if c.Curve() != protocol.Curve() {
			return errs.NewCurve("ci[%d] curve %s is not protocol curve %s", i,
				c.Curve().Name(), protocol.Curve().Name())
		}
		if (!freeCoefficientCanBeIdentity || i != 0) && c.IsAdditiveIdentity() {
			return errs.NewIsIdentity("ci[%d] is identity", i)
		}
	}
	if r1b.DlogProof == nil {
		return errs.NewIsNil("dlog proof")
	}
	return nil
}

func (r1p2p *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	if r1p2p.Xij == nil {
		return errs.NewIsNil("x_ij")
	}
	if r1p2p.Xij.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("x_ij curve %s is not protocol curve %s", r1p2p.Xij.ScalarField().Curve().Name(), protocol.Curve().Name())
	}
	if r1p2p.Xij.IsZero() {
		return errs.NewIsZero("x_ij is zero")
	}
	return nil
}

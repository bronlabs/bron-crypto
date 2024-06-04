package agreeonrandom_testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ fu.ObjectAdapter[*AgreeOnRandomPublicParameters] = (*AgreeOnRandomPPAdapter)(nil)

type AgreeOnRandomPublicParameters struct {
	Curve      curves.Curve
	Identities []types.IdentityKey
	Prng       io.Reader
}

type AgreeOnRandomPPAdapter struct {
}

func (sa *AgreeOnRandomPPAdapter) Wrap(x fu.Underlyer) *AgreeOnRandomPublicParameters {
	// nIdentities := (&fu.IntegerAdapter[int]{}).Wrap(x)
	return &AgreeOnRandomPublicParameters{}
	// TODO: How to mix adapters properly
}

func (*AgreeOnRandomPPAdapter) Unwrap(s *AgreeOnRandomPublicParameters) fu.Underlyer {
	return 0
}

func (sa *AgreeOnRandomPPAdapter) ZeroValue() *AgreeOnRandomPublicParameters {
	return &AgreeOnRandomPublicParameters{
		Curve:      edwards25519.NewCurve(),
		Identities: nil,
		Prng:       nil,
	}
}

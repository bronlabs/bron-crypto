//go:generate go run -tags codegen ../../impl/fields/codegen pkg/base/curves/pasta/impl
package impl

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl/internal/fiat"
)

//nolint:tagliatelle // embedded fields
type Fp struct {
	fields.SqrtTrait[*Fp, Fp]           `fiat:"sqrt_trait"`
	fiat.FpMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001,primitive_element=5"`
}

//nolint:tagliatelle // embedded fields
type Fq struct {
	fields.SqrtTrait[*Fq, Fq]           `fiat:"sqrt_trait"`
	fiat.FqMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001,primitive_element=5"`
}

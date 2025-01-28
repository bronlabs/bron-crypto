//go:generate go run -tags codegen ../../impl/fields/codegen pkg/base/curves/p256/impl
package impl

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256/impl/internal/fiat"
)

//nolint:tagliatelle // embedded fields
type Fp struct {
	fields.SqrtTrait[*Fp, Fp]           `fiat:"sqrt_trait"`
	fiat.FpMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,primitive_element=6"`
}

//nolint:tagliatelle // embedded fields
type Fq struct {
	fields.SqrtTrait[*Fq, Fq]           `fiat:"sqrt_trait"`
	fiat.FqMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,primitive_element=7"`
}

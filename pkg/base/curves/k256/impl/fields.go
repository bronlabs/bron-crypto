//go:generate go run -tags codegen ../../impl/fields/codegen pkg/base/curves/k256/impl
package impl

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl/internal/fiat"
)

//nolint:tagliatelle // embedded fields
type Fp struct {
	fields.SqrtTrait[*Fp, Fp]           `fiat:"sqrt_trait"`
	fiat.FpMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,primitive_element=3"`
}

//nolint:tagliatelle // embedded fields
type Fq struct {
	fields.SqrtTrait[*Fq, Fq]           `fiat:"sqrt_trait"`
	fiat.FqMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,primitive_element=7"`
}

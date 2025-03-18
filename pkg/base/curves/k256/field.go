package k256

// import (
// 	"sync"

// 	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
// 	k256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl"
// )

// var (
// 	baseFieldInitOnce sync.Once
// 	baseFieldInstance BaseField

// 	_ fields.PrimeField[BaseFieldElement]        = BaseField{}
// 	_ fields.PrimeFieldElement[BaseFieldElement] = BaseFieldElement{}
// )

// func baseFieldInit() {
// 	baseFieldInstance = BaseField{}
// }

// func NewBaseField() BaseField {
// 	baseFieldInitOnce.Do(baseFieldInit)
// 	return baseFieldInstance
// }

// type BaseField struct{}

// type BaseFieldElement struct {
// 	v k256Impl.Fp
// }

// func (e BaseFieldElement) Add(other BaseFieldElement) BaseFieldElement {
// 	out := new(k256Impl.Fp)
// 	out.Add(&e.v, &other.v)
// 	return BaseFieldElement{v: *out}
// }

// func (e BaseFieldElement) Mul(other BaseFieldElement) BaseFieldElement {
// 	out := new(k256Impl.Fp)
// 	out.Mul(&e.v, &other.v)
// 	return BaseFieldElement{v: *out}
// }

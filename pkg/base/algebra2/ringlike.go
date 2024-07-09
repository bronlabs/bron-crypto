package algebra

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/cronokirby/saferith"
)

// ******************** DistributiveBiMagma
// === Interfaces
type DistributiveBiMagma[BM BiStructure[BM, BME, OpAdd, OpMul], BME DistributiveBiMagmaElement[BME], OpAdd Addition[BME], OpMul Multiplication[BME]] interface {
	BiStructure[BM, BME, OpAdd, OpMul]
	MagmaticAdditiveness[BM]
	MagmaticMultiplicativeness[BM]

	DistributiveBiStructure[BME, OpMul, OpAdd]
}

type DistributiveBiMagmaElement[BME Element[BME]] interface {
	Element[BME]
	MagmaElementalAdditiveness[BME]
	MagmaElementalMultiplicativeness[BME]

	Characteristic() *saferith.Nat
	MulAdd(p, q BME) BME
}

// ******************** SemiRing
// === Interfaces

type SemiRing[R DistributiveBiMagma[R, RE, OpAdd, OpMul], RE SemiRingElement[RE], OpAdd Addition[RE], OpMul Multiplication[RE]] interface {
	DistributiveBiMagma[R, RE, OpAdd, OpMul]
	MonoidalMultiplicativeness[RE]
	StructuralUnitality[RE]

	CommutativeStructure[RE, OpAdd]
	AssociativeBiStructure[RE, OpAdd, OpMul]
}

type SemiRingElement[RE Element[RE]] interface {
	DistributiveBiMagmaElement[RE]
	MonoidElementalMultiplicativeness[RE]
	ElementalUnitality[RE]
}

// === Aspects

type StructuralUFDness[E any] interface{}

type ElementalUFDness[E any] interface {
	IsCoPrime(with E) bool
	GCD(x E) E
	LCM(x E) E
	Factorise() []ds.Map[E, Multiplicity]
	IsProbablyPrime() bool
}

// ******************** Rig
// === Interfaces

type Rig[R SemiRing[R, RE, OpAdd, OpMul], RE RigElement[RE], OpAdd Addition[RE], OpMul Multiplication[RE]] interface {
	SemiRing[R, RE, OpAdd, OpMul]
	MonoidalAdditiveness[RE]
}

type RigElement[RE SemiRingElement[RE]] interface {
	SemiRingElement[RE]
	MonoidElementalAdditiveness[RE]
}

// === Aspects

type StructuralEuclideanness[E any] interface {
	StructuralUFDness[E]
}

type ElementalEuclideanness[E any] interface {
	ElementalUFDness[E]
	EuclideanDiv(rhs E) (quot, rem E, err error)
}

// ******************** Rng
// === Interfaces

type Rng[R DistributiveBiMagma[R, RE, OpAdd, OpMul], RE RngElement[RE], OpAdd Addition[RE], OpMul Multiplication[RE]] interface {
	DistributiveBiMagma[R, RE, OpAdd, OpMul]
	GroupalAdditiveness[RE]

	CommutativeStructure[RE, OpAdd]
	AssociativeBiStructure[RE, OpAdd, OpMul]
}

type RngElement[RE DistributiveBiMagmaElement[RE]] interface {
	DistributiveBiMagmaElement[RE]
	GroupElementalAdditiveness[RE]
}

// ******************** Ring
// === Interfaces
type Ring[R DistributiveBiMagma[R, RE, OpAdd, OpMul], RE RingElement[RE], OpAdd Addition[RE], OpMul Multiplication[RE]] interface {
	// TODO: write a test to make sure ring is rng and a rig
	SemiRing[R, RE, OpAdd, OpMul]
	GroupalAdditiveness[RE]
}

type RingElement[RE DistributiveBiMagmaElement[RE]] interface {
	SemiRingElement[RE]
	GroupElementalAdditiveness[RE]
}

type AbelianRing[R Ring[R, RE, OpAdd, OpMul], RE AbelianRingElement[RE], OpAdd Addition[RE], OpMul Multiplication[RE]] interface {
	Ring[R, RE, OpAdd, OpMul]
	CommutativeStructure[RE, OpMul]
}

type AbelianRingElement[RE RingElement[RE]] interface {
	RingElement[RE]
}

// ******************** Domains
// === Interfaces

type UFD[D Ring[D, DE, OpAdd, OpMul], DE UFDElement[DE], OpAdd Addition[DE], OpMul Multiplication[DE]] interface {
	Ring[D, DE, OpAdd, OpMul]
	StructuralUFDness[DE]
}

type UFDElement[DE RingElement[DE]] interface {
	RingElement[DE]
	ElementalUFDness[DE]
}

type EuclideanDomain[D Ring[D, DE, OpAdd, OpMul], DE EuclideanDomainElement[DE], OpAdd Addition[DE], OpMul Multiplication[DE]] interface {
	UFD[D, DE, OpAdd, OpMul]
	StructuralEuclideanness[DE]
}

type EuclideanDomainElement[DE UFDElement[DE]] interface {
	UFDElement[DE]
	ElementalEuclideanness[DE]
}

// ******************** Fields
// === Interfaces

type Field[F EuclideanDomain[F, FE, OpAdd, OpMul], FE FieldElement[FE], OpAdd Addition[FE], OpMul Multiplication[FE]] interface {
	EuclideanDomain[F, FE, OpAdd, OpMul]
	GroupalMultiplicativeness[FE]
}

type FieldElement[FE EuclideanDomainElement[FE]] interface {
	EuclideanDomainElement[FE]
	MultiplicativeGroupElementInvertibleness[FE]
	Div(rhs FE) (FE, error)
}

type AbelianField[F Field[F, FE, OpAdd, OpMul], FE AbelianFieldElement[FE], OpAdd Addition[FE], OpMul Multiplication[FE]] interface {
	Field[F, FE, OpAdd, OpMul]
	AbelianRing[F, FE, OpAdd, OpMul]
}

type AbelianFieldElement[FE FieldElement[FE]] interface {
	FieldElement[FE]
	AbelianRingElement[FE]
}

type FiniteField[F AbelianField[F, FE, OpAdd, OpMul], FE FiniteFieldElement[FE], OpAdd Addition[FE], OpMul Multiplication[FE]] interface {
	AbelianField[F, FE, OpAdd, OpMul]
	FiniteStructure[FE]
}

type FiniteFieldElement[FE AbelianFieldElement[FE]] interface {
	AbelianFieldElement[FE]
}

// ******************** Field Extensions

type ExtensionField[EF Field[EF, EFE, OpAdd, OpMul], PF Field[PF, PFE, UOpAdd, UOpMul], EFE ExtensionFieldElement[EFE, PFE], PFE FieldElement[PFE], OpAdd Addition[EFE], OpMul Multiplication[EFE], UOpAdd Addition[PFE], UOpMul Multiplication[PFE]] interface {
	Field[EF, EFE, OpAdd, OpMul]
	BiSuperStructure[EF, PF, EFE, OpAdd, OpMul]
	ExtensionDegree() uint
	// SubFieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubFieldIdentity(i uint) (any, error)
}

type ExtensionFieldElement[EFE FieldElement[EFE], PFE FieldElement[PFE]] interface {
	FieldElement[EFE]
	// Norm returns determinant of the linear transformation this*x in the vector space formed by S and its basefield.
	// eg. in a quadratic field extension of a finite field output is this * this.Conjugate()
	Norm() PFE
	Conjugate() PFE
}

package curves2

type Scalar interface {
	PrimeFieldElement
	Curve() Curve
}

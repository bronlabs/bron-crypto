package k256

// import (
// 	"sync"

// 	curves "github.com/bronlabs/krypton-primitives/pkg/base/curves2"
// 	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
// )

const (
	Name                  = "secp256k1"
	Hash2CurveSuite       = "secp256k1_XMD:SHA-256_SSWU_RO_"
	Hash2CurveScalarSuite = "secp256k1_XMD:SHA-256_SSWU_RO_SC_"
)

// var (
// 	k256InitOnce sync.Once
// 	k256Instance Curve
// )

// var _ curves.Curve[Point, Scalar, BaseFieldElement] = Curve{}

// type Curve struct {
// 	_ ds.Incomparable
// }

// func k256Init() {
// 	k256Instance = Curve{}
// }

// func NewCurve() *Curve {
// 	k256InitOnce.Do(k256Init)
// 	return &k256Instance
// }

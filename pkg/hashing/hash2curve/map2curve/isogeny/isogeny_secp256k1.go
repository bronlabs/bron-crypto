package hash2curve

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// IsogenyParamsSecp256k1 are parameters needed to map from an isogeny to Secp256k1.
// See https://datatracker.ietf.org/doc/html/rfc9380#name-3-isogeny-map-for-secp256k1
type IsogenyParamsSecp256k1 struct {
	K1 [4]curves.FieldElement
	K2 [2]curves.FieldElement
	K3 [4]curves.FieldElement
	K4 [3]curves.FieldElement
	_  types.Incomparable
}

func NewIsogenyParamsSecp256k1(curve curves.Curve) *IsogenyParamsSecp256k1 {
	return &IsogenyParamsSecp256k1{
		K1: [4]curves.FieldElement{
			ReadConstant(curve, "8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7"),  // k_(1,0)
			ReadConstant(curve, "07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581"),  // k_(1,1)
			ReadConstant(curve, "534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262"),  // k_(1,2)
			ReadConstant(curve, "8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c")}, // k_(1,3)
		K2: [2]curves.FieldElement{
			ReadConstant(curve, "d35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b"),  // k_(2,0)
			ReadConstant(curve, "edadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14")}, // k_(2,1)
		K3: [4]curves.FieldElement{
			ReadConstant(curve, "4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c"),  // k_(3,0)
			ReadConstant(curve, "c75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3"),  // k_(3,1)
			ReadConstant(curve, "29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931"),  // k_(3,2)
			ReadConstant(curve, "2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84")}, // k_(3,3)
		K4: [3]curves.FieldElement{
			ReadConstant(curve, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b"),  // k_(4,0)
			ReadConstant(curve, "7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573"),  // k_(4,1)
			ReadConstant(curve, "6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f")}, // k_(4,2)
	}
}

// IsogenyMapSecp256k1 maps from (x', y') on E' to (x, y) on Secp256k1,
// given by the following rational functions:
//
// - x = x_num / x_den, where
//   - x_num = k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)
//   - x_den = x'^2 + k_(2,1) * x' + k_(2,0)
//
// - y = y' * y_num / y_den, where
//   - y_num = k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)
//   - y_den = x'^3 + k_(4,2) * x'^2 + k_(4,1) * x' + k_(4,0)
func (params *IsogenyParamsSecp256k1) IsogenyMap(xPrime curves.FieldElement) (xNum, xDen, yNum, yDen curves.FieldElement) {
	// Compute x_num
	xPrimeSquare := xPrime.Square()
	xPrimeCube := xPrimeSquare.Mul(xPrime)
	xNum = params.K1[3].Mul(xPrimeCube)
	xNum = params.K1[2].MulAdd(xPrimeSquare, xNum)
	xNum = params.K1[1].MulAdd(xPrime, xNum)
	xNum = params.K1[0].Add(xNum)

	// Compute x_den
	xDen = params.K2[1].MulAdd(xPrimeSquare, params.K2[0])

	// Compute y_num
	yNum = params.K3[3].Mul(xPrimeCube)
	yNum = params.K3[2].MulAdd(xPrimeSquare, yNum)
	yNum = params.K3[1].MulAdd(xPrime, yNum)
	yNum = params.K3[0].Add(yNum)

	// Compute y_den
	yDen = params.K4[2].MulAdd(xPrimeSquare, xPrimeCube)
	yDen = params.K4[1].MulAdd(xPrime, yDen)
	yDen = params.K4[0].Add(yDen)
	return xNum, xDen, yNum, yDen
}

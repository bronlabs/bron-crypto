package hash2curve

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

// IsogenyParamsBLS12381G2 are parameters needed to map from an isogeny to BLS12381G2.
// See https://datatracker.ietf.org/doc/html/rfc9380#appendix-E.3
type IsogenyParamsBLS12381G2 struct {
	K1  [4]curves.FieldElement
	K1I [4]curves.FieldElement
	K2  [2]curves.FieldElement
	K2I [2]curves.FieldElement
	K3  [4]curves.FieldElement
	K3I [4]curves.FieldElement
	K4  [3]curves.FieldElement
	K4I [3]curves.FieldElement
}

func NewIsogenyParamsBLS12381G2(curve curves.Curve) *IsogenyParamsBLS12381G2 {
	return &IsogenyParamsBLS12381G2{
		K1: [4]curves.FieldElement{
			ReadConstant(curve, "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"), // k_(1,0)
			nil, // k_(1,1)
			ReadConstant(curve, "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e"),  // k_(1,2)
			ReadConstant(curve, "171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1")}, // k_(1,3)
		K1I: [4]curves.FieldElement{
			ReadConstant(curve, "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"), // k_(1,0)
			ReadConstant(curve, "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"), // k_(1,1)
			ReadConstant(curve, "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"), // k_(1,2)
			nil}, // k_(1,3)
		K2: [2]curves.FieldElement{
			nil,                        // k_(2,0)
			ReadConstant(curve, "0c")}, // k_(2,1)
		K2I: [2]curves.FieldElement{
			ReadConstant(curve, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"),  // k_(2,0)
			ReadConstant(curve, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f")}, // k_(2,1)
		K3: [4]curves.FieldElement{
			ReadConstant(curve, "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"), // k_(3,0)
			nil, // k_(3,1)
			ReadConstant(curve, "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c"),  // k_(3,2)
			ReadConstant(curve, "124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10")}, // k_(3,3)
		K3I: [4]curves.FieldElement{
			ReadConstant(curve, "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"), // k_(3,0)
			ReadConstant(curve, "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"), // k_(3,1)
			ReadConstant(curve, "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"), // k_(3,2)
			nil}, // k_(3,3)
		K4: [3]curves.FieldElement{
			ReadConstant(curve, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"), // k_(4,0)
			nil,                         // k_(4,1)
			ReadConstant(curve, "0x12"), // k_(4,2)
		},
		K4I: [3]curves.FieldElement{
			ReadConstant(curve, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"), // k_(4,0)
			ReadConstant(curve, "1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d"), // k_(4,1)
			ReadConstant(curve, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"), // k_(4,2)
		},
	}
}

// IsogenyMap maps from an isogeny to BLS12381G2. The 3-isogeny map from (x', y')
//
//	on E' to (x, y) on E is given by the following rational functions:
//
// - x = x_num / x_den, where
//   - x_num = k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)
//   - x_den = x'^2 + k_(2,1) * x' + k_(2,0)
//
// - y = y' * y_num / y_den, where
//   - y_num = k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)
//   - y_den = x'^3 + k_(4,2) * x'^2 + k_(4,1) * x' + k_(4,0)
func (params *IsogenyParamsBLS12381G2) IsogenyMap(xPrime curves.FieldElement) (xNum, xDen, yNum, yDen curves.FieldElement) {
	xNum = params.K1[0].MulAdd(xPrime, params.K1[1])
	xDen = params.K2[0].MulAdd(xPrime, params.K2[1])
	yNum = params.K3[0].MulAdd(xPrime, params.K3[1])
	yDen = params.K4[0].MulAdd(xPrime, params.K4[1])
	// TODO: Finish this
	return xNum, xDen, yNum, yDen
}

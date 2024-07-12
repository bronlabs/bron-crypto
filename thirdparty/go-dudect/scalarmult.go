package main

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	//"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
)

// the DUDECT functions :
func prepare_inputs() (input_data [][]byte, classes []int) {
	classes = make([]int, number_measurements)
	input_data = make([][]byte, number_measurements)
	rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	for i := 0; i < number_measurements; i++ {
		classes[i] = rn.Intn(2)
		// class 0 inputs contain 0s only
		if classes[i] == 0 {
			input_data[i] = make([]byte, 32)
		} else {
			// class 1 inputs are random
			input_data[i] = make([]byte, 32)
			for j := 0; j < 32; j++ {
				rand.Read(input_data[i])
			}
		}
	}
	return input_data, classes
}

func do_one_computation(data []byte) {
	// edwards25519
	//curve := edwards25519.NewCurve()

	// bls12-381
	curve := bls12381.NewG2()

	scalar, _ := curve.HashToScalars(1, data, nil)
	point := curve.BasePoint().ScalarMul(scalar[0])
	// to make sure the compiler does not throw the above calculations away
	if point.IsAdditiveIdentity() {
		fmt.Errorf("is additive identity: %s", string(point.ToAffineCompressed()))
	}
}

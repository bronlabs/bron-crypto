package main

import (
	"crypto/rand"
	crand "crypto/rand"
	mrand "math/rand"
	"time"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	//hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	elgamalcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/elgamal"
	//pedersencommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/pedersen"
)

// the DUDECT functions :

func prepare_inputs() (input_data [][]byte, classes []int) {
	classes = make([]int, number_measurements)
	input_data = make([][]byte, number_measurements)
	rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	for i := 0; i < number_measurements; i++ {
		classes[i] = rn.Intn(2)
		// compute hash-based commitments over 512 bytes (threshold value may exceed 5 w/ 256)
		// class 0 inputs contain 0s only
		if classes[i] == 0 {
			input_data[i] = make([]byte, 512)
		} else {
			// class 1 inputs are random
			input_data[i] = make([]byte, 512)
			for j := 0; j < 512; j++ {
				rand.Read(input_data[i])
			}
		}
	}
	return input_data, classes
}

func do_one_computation(data []byte) {
	// hashcommitments
	//committer, _ := hashcommitments.NewCommitter([]byte{0}, crand.Reader)
	//committer.Commit(data)

	// pedersencommitments
	//curve := edwards25519.NewCurve()
	//scalar, _ := curve.HashToScalars(1, data, nil)
	//committer, _ := pedersencommitments.NewCommitter([]byte{0}, curve, crand.Reader)

	// elgamalcommitments
	curve := edwards25519.NewCurve()
	scalar, _ := curve.HashToScalars(1, data, nil)
	committer, _ := elgamalcommitments.NewCommitter([]byte{0}, curve.BasePoint(), crand.Reader)
	committer.Commit(curve.BasePoint().ScalarMul(scalar[0]))
}

package main

import (
	"crypto/rand"
	mrand "math/rand"
	"time"
	//"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
)

// the DUDECT functions :
func prepare_inputs() (input_data [][]byte, classes []int) {
	classes = make([]int, number_measurements)
	input_data = make([][]byte, number_measurements)
	rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	for i := 0; i < number_measurements; i++ {
		classes[i] = rn.Intn(2)
		// class 0 inputs contain the same 64-byte data twice
		if classes[i] == 0 {
			input_data[i] = make([]byte, 128)
			for j := 0; j < 64; j++ {
				rand.Read(input_data[i])
			}
			for j := 64; j < 128; j++ {
				input_data[i][j] = input_data[i][j-64]
			}
		} else {
			// class 1 inputs are random
			input_data[i] = make([]byte, 128)
			for j := 0; j < 128; j++ {
				rand.Read(input_data[i])
			}
		}
	}
	return input_data, classes
}

func dummy_compare(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func do_one_computation(data []byte) {
	//ct.SliceCmpLE(data[:64], data[64:])
	dummy_compare(data[:64], data[64:])
}

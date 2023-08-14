package internal

import "math/big"

func Bhex(s string) *big.Int {
	r, _ := new(big.Int).SetString(s, 16)
	return r
}

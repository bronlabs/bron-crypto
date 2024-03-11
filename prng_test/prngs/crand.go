package prngs

import (
	crand "crypto/rand"
	"io"
)

type CrandPrngTest struct {
}

func (c *CrandPrngTest) GetPrng() (io.Reader, error) {
	return crand.Reader, nil
}


package saferith

import (
	"testing"
)

var saferithNats = &SNats{}

func TestSaferithNat_Add(t *testing.T) {
	x := saferithNats.NewUint64(1234)
	y := saferithNats.NewUint64(4567)
	_ = saferithNats.New().Add(x, y, -1)
}

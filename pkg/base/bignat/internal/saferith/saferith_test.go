package saferith

import (
	nats2 "github.com/copperexchange/krypton-primitives/pkg/base/bignat/internal/saferith/nats"
	"testing"
)

func TestSaferithNat_Add(t *testing.T) {
	nats := nats2.NewNats()
	x := nats.NewUint64(1234)
	y := nats.NewUint64(4567)
	_ = nats.New().Add(x, y, -1)
}

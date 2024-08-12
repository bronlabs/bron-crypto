package bls12381

import (
	"encoding/gob"
	"sync"
)

var (
	registerOnce sync.Once
)

func RegisterForGob() {
	registerOnce.Do(func() {
		gob.Register(new(G1))
		gob.Register(new(G2))
		gob.Register(new(PointG1))
		gob.Register(new(PointG2))
		gob.Register(new(GtMember))
		gob.Register(new(Scalar))
		gob.Register(new(BaseFieldElementG1))
		gob.Register(new(BaseFieldElementG2))
	})
}

package k256

import (
	"encoding/gob"
	"sync"
)

var (
	registerOnce sync.Once
)

func RegisterForGob() {
	registerOnce.Do(func() {
		gob.Register(new(Point))
		gob.Register(new(Scalar))
		gob.Register(new(BaseFieldElement))
	})
}

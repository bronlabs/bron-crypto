package pasta

import (
	"encoding/gob"
	"sync"
)

var (
	registerOnce sync.Once
)

func RegisterForGob() {
	registerOnce.Do(func() {
		gob.Register(new(PallasPoint))
		gob.Register(new(PallasScalar))
		gob.Register(new(PallasBaseFieldElement))
		gob.Register(new(VestaPoint))
		gob.Register(new(VestaScalar))
		gob.Register(new(VestaBaseFieldElement))
	})
}

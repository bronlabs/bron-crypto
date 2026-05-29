package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"pgregory.net/rapid"
)

type WitnessGenerator[W commitments.Witness] = rapid.Generator[W]

type WitnessProperties[W commitments.Witness] struct {
	WitnessGenerator *WitnessGenerator[W]

	WitnessesAreEqual func(W, W) bool
}

func (p *WitnessProperties[W]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", p.IsCBORSerialisable)
}

func (p *WitnessProperties[W]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[W]{
		Generator: p.WitnessGenerator,
		AreEqual:  p.WitnessesAreEqual,
	}
	serialisationSuite.CheckAll(t)
}

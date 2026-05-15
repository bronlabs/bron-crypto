package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"pgregory.net/rapid"
)

type PlaintextGenerator[P encryption.Plaintext] = rapid.Generator[P]

type PlaintextProperties[P encryption.Plaintext] struct {
	PlaintextGenerator *PlaintextGenerator[P]
	PlaintextsAreEqual func(P, P) bool
}

func (p *PlaintextProperties[P]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", p.IsCBORSerialisable)
}

func (p *PlaintextProperties[P]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[P]{
		Generator: p.PlaintextGenerator,
		AreEqual:  p.PlaintextsAreEqual,
	}
	serialisationSuite.CheckAll(t)
}

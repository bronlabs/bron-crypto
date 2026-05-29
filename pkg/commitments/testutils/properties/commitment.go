package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"pgregory.net/rapid"
)

type CommitmentGenerator[C commitments.Commitment[C]] = rapid.Generator[C]

type CommitmentProperties[C commitments.Commitment[C]] struct {
	CommitmentGenerator *CommitmentGenerator[C]

	CommitmentsAreEqual func(C, C) bool
}

func (p *CommitmentProperties[C]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", p.IsCBORSerialisable)
}

func (p *CommitmentProperties[C]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[C]{
		Generator: p.CommitmentGenerator,
		AreEqual:  p.CommitmentsAreEqual,
	}
	serialisationSuite.CheckAll(t)
}

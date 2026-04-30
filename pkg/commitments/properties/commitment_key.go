package properties

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/properties"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type (
	CommitmentKeyGenerator[K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]]                                 = rapid.Generator[K]
	HomomorphicCommitmentKeyGenerator[K commitments.HomomorphicCommitmentKey[K, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any] = rapid.Generator[K]
	GroupHomomorphicCommitmentKeyGenerator[
		K commitments.GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
		M interface {
			commitments.Message
			base.Transparent[MV]
		}, MG algebra.Group[MV], MV algebra.GroupElement[MV],
		W interface {
			commitments.Witness
			base.Transparent[WV]
		}, WG algebra.Group[WV], WV algebra.GroupElement[WV],
		C interface {
			commitments.Commitment[C]
			base.Transparent[CV]
		}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
		S any,
	] = rapid.Generator[K]
)

type CommitmentKeyProperties[K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]] struct {
	PRNG                   func() io.Reader
	CommitmentKeyGenerator *CommitmentKeyGenerator[K, M, W, C]
	MessageGenerator       *MessageGenerator[M]

	MessagesAreEqual  func(M, M) bool
	WitnessesAreEqual func(W, W) bool
}

func (p *CommitmentKeyProperties[K, M, W, C]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", p.IsCBORSerialisable)
	t.Run("CommitOpenRoundtrip", p.CommitOpenRoundtrip)
	t.Run("SameMessageWitnessSameCommitment", p.SameMessageWitnessSameCommitment)
	t.Run("DifferentWitnessSameMessageDifferentCommitment", p.DifferentWitnessSameMessageDifferentCommitment)
	t.Run("SameWitnessDifferentMessageDifferentCommitment", p.SameWitnessDifferentMessageDifferentCommitment)
	t.Run("CantOpenWithWrongWitness", p.CantOpenWithWrongWitness)
	t.Run("CantOpenWithWrongMessage", p.CantOpenWithWrongMessage)
	t.Run("CantOpenWithDifferentKey", p.CantOpenWithDifferentKey)
	t.Run("DifferentKeysSameMessageWitnessDifferentCommitment", p.DifferentKeysSameMessageWitnessDifferentCommitment)
	t.Run("CantOpenWithDifferentCommitment", p.CantOpenWithDifferentCommitment)
	t.Run("CommitMatchesCommitWithWitness", p.CommitMatchesCommitWithWitness)
}

func (p *CommitmentKeyProperties[K, M, W, C]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[K]{
		Generator: p.CommitmentKeyGenerator,
		AreEqual:  func(a, b K) bool { return a.Equal(b) },
	}
	serialisationSuite.CheckAll(t)
}

func (p *CommitmentKeyProperties[K, M, W, C]) CommitOpenRoundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		err = key.Open(commitment, message, witness)
		require.NoError(t, err)
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) SameMessageWitnessSameCommitment(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment1, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		commitment2, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		require.True(t, commitment1.Equal(commitment2))
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) DifferentWitnessSameMessageDifferentCommitment(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness1, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		witness2, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment1, err := key.CommitWithWitness(message, witness1)
		require.NoError(t, err)

		commitment2, err := key.CommitWithWitness(message, witness2)
		require.NoError(t, err)

		require.Equal(t, p.WitnessesAreEqual(witness1, witness2), commitment1.Equal(commitment2))
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) SameWitnessDifferentMessageDifferentCommitment(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message1 := p.MessageGenerator.Draw(rt, "message1")
		message2 := p.MessageGenerator.Filter(func(m M) bool {
			return !p.MessagesAreEqual(message1, m)
		}).Draw(rt, "message2")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment1, err := key.CommitWithWitness(message1, witness)
		require.NoError(t, err)

		commitment2, err := key.CommitWithWitness(message2, witness)
		require.NoError(t, err)

		require.Equal(t, p.MessagesAreEqual(message1, message2), commitment1.Equal(commitment2))
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CantOpenWithWrongWitness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness1, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		var witness2 W
		for {
			witness2, err = key.SampleWitness(p.PRNG())
			require.NoError(t, err)
			if !p.WitnessesAreEqual(witness1, witness2) {
				break
			}
		}

		commitment, err := key.CommitWithWitness(message, witness1)
		require.NoError(t, err)

		err = key.Open(commitment, message, witness2)
		require.Error(t, err)
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CantOpenWithWrongMessage(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message1 := p.MessageGenerator.Draw(rt, "message1")
		message2 := p.MessageGenerator.Filter(func(m M) bool {
			return !p.MessagesAreEqual(message1, m)
		}).Draw(rt, "message2")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message1, witness)
		require.NoError(t, err)

		err = key.Open(commitment, message2, witness)
		require.Error(t, err)
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CantOpenWithDifferentKey(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key1 := p.CommitmentKeyGenerator.Draw(rt, "commitment key 1")
		key2 := p.CommitmentKeyGenerator.Filter(func(k K) bool {
			return !k.Equal(key1)
		}).Draw(rt, "commitment key 2")

		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key1.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key1.CommitWithWitness(message, witness)
		require.NoError(t, err)

		err = key2.Open(commitment, message, witness)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) DifferentKeysSameMessageWitnessDifferentCommitment(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key1 := p.CommitmentKeyGenerator.Draw(rt, "commitment key 1")
		key2 := p.CommitmentKeyGenerator.Filter(func(k K) bool {
			return !k.Equal(key1)
		}).Draw(rt, "commitment key 2")

		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key1.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment1, err := key1.CommitWithWitness(message, witness)
		require.NoError(t, err)

		commitment2, err := key2.CommitWithWitness(message, witness)
		require.NoError(t, err)

		require.False(t, commitment1.Equal(commitment2))
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CantOpenWithDifferentCommitment(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")

		message1 := p.MessageGenerator.Draw(rt, "message1")
		message2 := p.MessageGenerator.Filter(func(m M) bool {
			return !p.MessagesAreEqual(message1, m)
		}).Draw(rt, "message2")

		witness1, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		var witness2 W
		for {
			witness2, err = key.SampleWitness(p.PRNG())
			require.NoError(t, err)
			if !p.WitnessesAreEqual(witness1, witness2) {
				break
			}
		}

		commitment1, err := key.CommitWithWitness(message1, witness1)
		require.NoError(t, err)

		commitment2, err := key.CommitWithWitness(message2, witness2)
		require.NoError(t, err)

		err = key.Open(commitment1, message2, witness2)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)

		err = key.Open(commitment2, message1, witness1)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CommitMatchesCommitWithWitness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.CommitmentKeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		commitment, witness, err := commitments.Commit(key, message, p.PRNG())
		require.NoError(t, err)

		commitmentWithWitness, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		require.True(t, commitment.Equal(commitmentWithWitness))
	})
}

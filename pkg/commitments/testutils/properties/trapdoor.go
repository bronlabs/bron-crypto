package properties

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewTrapdoorKeyProperties[K commitments.CommitmentKey[K, M, W, C], T commitments.TrapdoorKey[K, T, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[T],
	messageGenerator func(testing.TB, commitments.CommitmentKey[T, M, W, C]) *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
) *TrapdoorKeyProperties[K, T, M, W, C] {
	tb.Helper()
	return &TrapdoorKeyProperties[K, T, M, W, C]{
		CommitmentKeyProperties: *NewCommitmentKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual),
	}
}

type TrapdoorKeyProperties[K commitments.CommitmentKey[K, M, W, C], T commitments.TrapdoorKey[K, T, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]] struct {
	CommitmentKeyProperties[T, M, W, C]
}

func (p *TrapdoorKeyProperties[K, T, M, W, C]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("CommitmentKeyProperties", p.CommitmentKeyProperties.CheckAll)
	t.Run("CanEquivocate", p.CanEquivocate)
	t.Run("EquivocateChangesWitnessForDifferentMessages", p.EquivocateChangesWitnessForDifferentMessages)
	t.Run("EquivocateDoesntChangeWitnessForSameMessage", p.EquivocateDoesntChangeWitnessForSameMessage)
	t.Run("CanExportCommitmentKey", p.CanExportCommitmentKey)
}

func (p *TrapdoorKeyProperties[K, T, M, W, C]) CanEquivocate(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "trapdoor key")
		message := p.MessageGenerator(t, key).Draw(rt, "message")
		alternateMessage := p.MessageGenerator(t, key).Filter(func(m M) bool { return !p.MessagesAreEqual(m, message) }).Draw(rt, "alternate message")
		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err, "failed to sample witness")
		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err, "failed to compute commitment")

		alternateWitness, err := key.Equivocate(message, witness, alternateMessage, p.PRNG())
		require.NoError(t, err, "failed to compute alternate witness")

		err = key.Open(commitment, alternateMessage, alternateWitness)
		require.NoError(t, err, "failed to open commitment with alternate message and witness")
	})
}

func (p *TrapdoorKeyProperties[K, T, M, W, C]) EquivocateChangesWitnessForDifferentMessages(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "trapdoor key")

		message := p.MessageGenerator(t, key).Draw(rt, "message")
		alternateMessage := p.MessageGenerator(t, key).Filter(func(m M) bool { return !p.MessagesAreEqual(m, message) }).Draw(rt, "alternate message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err, "failed to sample witness")
		alternateWitness, err := key.Equivocate(message, witness, alternateMessage, p.PRNG())
		require.NoError(t, err, "failed to compute alternate witness")

		require.False(t, p.WitnessesAreEqual(witness, alternateWitness), "witness should change when equivocating to a different message")
	})
}

func (p *TrapdoorKeyProperties[K, T, M, W, C]) EquivocateDoesntChangeWitnessForSameMessage(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "trapdoor key")

		message := p.MessageGenerator(t, key).Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err, "failed to sample witness")
		alternateWitness, err := key.Equivocate(message, witness, message, p.PRNG())
		require.NoError(t, err, "failed to compute alternate witness")

		require.True(t, p.WitnessesAreEqual(witness, alternateWitness), "witness should not change when equivocating to the same message")
	})
}

func (p *TrapdoorKeyProperties[K, T, M, W, C]) CanExportCommitmentKey(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		trapdoorKey := p.KeyGenerator.Draw(rt, "trapdoor key")
		message := p.MessageGenerator(t, trapdoorKey).Draw(rt, "message")
		witness, err := trapdoorKey.SampleWitness(p.PRNG())
		require.NoError(t, err, "failed to sample witness")
		commitment, err := trapdoorKey.CommitWithWitness(message, witness)
		require.NoError(t, err, "failed to compute commitment")
		exportedKey := trapdoorKey.Export()

		t.Run("ExportedKeyCanOpenCommitment", func(t *testing.T) {
			t.Parallel()
			err = exportedKey.Open(commitment, message, witness)
			require.NoError(t, err, "failed to open commitment with exported key")
		})

		t.Run("ExportedKeyCommitsToSameValue", func(t *testing.T) {
			t.Parallel()
			exportedCommitment, err := exportedKey.CommitWithWitness(message, witness)
			require.NoError(t, err, "failed to compute commitment with exported key")
			require.True(t, commitment.Equal(exportedCommitment), "commitment from trapdoor key and exported key should be equal")
		})
	})
}

func NewHomomorphicTrapdoorKeyProperties[K commitments.HomomorphicCommitmentKey[K, M, W, C, S], T commitments.HomomorphicTrapdoorKey[K, T, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[T],
	messageGenerator func(testing.TB, commitments.CommitmentKey[T, M, W, C]) *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
	scalarGenerator func(testing.TB, commitments.HomomorphicCommitmentKey[T, M, W, C, S]) *rapid.Generator[S],
) *HomomorphicTrapdoorKeyProperties[K, T, M, W, C, S] {
	tb.Helper()
	require.NotNil(tb, scalarGenerator)
	return &HomomorphicTrapdoorKeyProperties[K, T, M, W, C, S]{
		TrapdoorKeyProperties:              *NewTrapdoorKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual),
		HomomorphicCommitmentKeyProperties: *NewHomomorphicCommitmentKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual, scalarGenerator),
	}
}

type HomomorphicTrapdoorKeyProperties[K commitments.HomomorphicCommitmentKey[K, M, W, C, S], T commitments.HomomorphicTrapdoorKey[K, T, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any] struct {
	TrapdoorKeyProperties[K, T, M, W, C]
	HomomorphicCommitmentKeyProperties[T, M, W, C, S]
}

func (p *HomomorphicTrapdoorKeyProperties[K, T, M, W, C, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("TrapdoorKeyProperties", p.TrapdoorKeyProperties.CheckAll)
	t.Run("HomomorphicCommitmentKeyProperties", p.HomomorphicCommitmentKeyProperties.CheckAll)
}

func NewGroupHomomorphicTrapdoorKeyProperties[
	K commitments.GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
	T commitments.GroupHomomorphicTrapdoorKey[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S],
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
](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[T],
	messageGenerator func(testing.TB, commitments.CommitmentKey[T, M, W, C]) *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
	scalarGenerator func(testing.TB, commitments.HomomorphicCommitmentKey[T, M, W, C, S]) *rapid.Generator[S],
	commitmentGenerator func(testing.TB, commitments.CommitmentKey[T, M, W, C]) *rapid.Generator[C],
	newMessage func(MV) (M, error),
	newWitness func(WV) (W, error),
	newCommitment func(CV) (C, error),
	messageScalarOp func(testing.TB, M, S) M,
	witnessScalarOp func(testing.TB, W, S) W,
	commitmentScalarOp func(testing.TB, C, S) C,
) *GroupHomomorphicTrapdoorKeyProperties[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S] {
	tb.Helper()
	require.NotNil(tb, newMessage)
	require.NotNil(tb, newWitness)
	require.NotNil(tb, newCommitment)
	return &GroupHomomorphicTrapdoorKeyProperties[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S]{
		HomomorphicTrapdoorKeyProperties:        *NewHomomorphicTrapdoorKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual, scalarGenerator),
		GroupHomomorphicCommitmentKeyProperties: *NewGroupHomomorphicCommitmentKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual, scalarGenerator, commitmentGenerator, newMessage, newWitness, newCommitment, messageScalarOp, witnessScalarOp, commitmentScalarOp),
	}
}

type GroupHomomorphicTrapdoorKeyProperties[
	K commitments.GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
	T commitments.GroupHomomorphicTrapdoorKey[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S],
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
] struct {
	HomomorphicTrapdoorKeyProperties[K, T, M, W, C, S]
	GroupHomomorphicCommitmentKeyProperties[T, M, MG, MV, W, WG, WV, C, CG, CV, S]
}

func (p *GroupHomomorphicTrapdoorKeyProperties[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("HomomorphicTrapdoorKeyProperties", p.HomomorphicTrapdoorKeyProperties.CheckAll)
	t.Run("GroupHomomorphicCommitmentKeyProperties", p.GroupHomomorphicCommitmentKeyProperties.CheckAll)
}

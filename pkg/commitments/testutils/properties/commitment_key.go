package properties

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewCommitmentKeyProperties[K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[K],
	messageGenerator *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
) *CommitmentKeyProperties[K, M, W, C] {
	tb.Helper()
	require.NotNil(tb, prng)
	require.NotNil(tb, keyGenerator)
	require.NotNil(tb, messageGenerator)
	require.NotNil(tb, messagesAreEqual)
	require.NotNil(tb, witnessesAreEqual)
	return &CommitmentKeyProperties[K, M, W, C]{
		PRNG:              prng,
		KeyGenerator:      keyGenerator,
		MessageGenerator:  messageGenerator,
		MessagesAreEqual:  messagesAreEqual,
		WitnessesAreEqual: witnessesAreEqual,
	}
}

type CommitmentKeyProperties[K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]] struct {
	PRNG             func() io.Reader
	KeyGenerator     *rapid.Generator[K]
	MessageGenerator *MessageGenerator[M]

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
	t.Run("CommittingDoesntMutateAnything", p.CommittingDoesntMutateAnything)
}

func (p *CommitmentKeyProperties[K, M, W, C]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[K]{
		Generator: p.KeyGenerator,
		AreEqual:  func(a, b K) bool { return a.Equal(b) },
	}
	serialisationSuite.CheckAll(t)
}

func (p *CommitmentKeyProperties[K, M, W, C]) CommitOpenRoundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key := p.KeyGenerator.Draw(rt, "commitment key")
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
		key1 := p.KeyGenerator.Draw(rt, "commitment key 1")
		key2 := p.KeyGenerator.Filter(func(k K) bool {
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
		key1 := p.KeyGenerator.Draw(rt, "commitment key 1")
		key2 := p.KeyGenerator.Filter(func(k K) bool {
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
		key := p.KeyGenerator.Draw(rt, "commitment key")

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
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		commitment, witness, err := commitments.Commit(key, message, p.PRNG())
		require.NoError(t, err)

		commitmentWithWitness, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		require.True(t, commitment.Equal(commitmentWithWitness))
	})
}

func (p *CommitmentKeyProperties[K, M, W, C]) CommittingDoesntMutateAnything(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		// We have no reflect.DeepCopy so have to do this trick.
		keyMarshalled, err := serde.MarshalCBOR(key)
		require.NoError(t, err)
		messageMarshalled, err := serde.MarshalCBOR(message)
		require.NoError(t, err)
		witnessMarshalled, err := serde.MarshalCBOR(witness)
		require.NoError(t, err)

		_, err = key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		postKeyMarshalled, err := serde.MarshalCBOR(key)
		require.NoError(t, err)
		postMessageMarshalled, err := serde.MarshalCBOR(message)
		require.NoError(t, err)
		postWitnessMarshalled, err := serde.MarshalCBOR(witness)
		require.NoError(t, err)

		require.EqualValues(t, messageMarshalled, postMessageMarshalled)
		require.EqualValues(t, witnessMarshalled, postWitnessMarshalled)
		require.EqualValues(t, keyMarshalled, postKeyMarshalled)
	})
}

func NewHomomorphicCommitmentKeyProperties[K commitments.HomomorphicCommitmentKey[K, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[K],
	messageGenerator *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
	scalarGenerator *rapid.Generator[S],
) *HomomorphicCommitmentKeyProperties[K, M, W, C, S] {
	tb.Helper()
	require.NotNil(tb, scalarGenerator)
	return &HomomorphicCommitmentKeyProperties[K, M, W, C, S]{
		CommitmentKeyProperties: *NewCommitmentKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual),
		ScalarGenerator:         scalarGenerator,
	}
}

type HomomorphicCommitmentKeyProperties[K commitments.HomomorphicCommitmentKey[K, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any] struct {
	CommitmentKeyProperties[K, M, W, C]
	ScalarGenerator *rapid.Generator[S]
}

func (p *HomomorphicCommitmentKeyProperties[K, M, W, C, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("CommitmentKeyProperties", p.CommitmentKeyProperties.CheckAll)
	t.Run("CommitmentMultIsMessageWitnessAdd", p.CommitmentMultIsMessageWitnessAdd)
	t.Run("CommitmentScalarOpIsMessageWitnessScalarOp", p.CommitmentScalarOpIsMessageWitnessScalarOp)
	t.Run("ReRandomiseShiftsWitness", p.ReRandomiseShiftsWitness)
	t.Run("CanShiftCommitmentByMessage", p.CanShiftCommitmentByMessage)
}

func (p *HomomorphicCommitmentKeyProperties[K, M, W, C, S]) CommitmentMultIsMessageWitnessAdd(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		m1 := p.MessageGenerator.Draw(rt, "message 1")
		m2 := p.MessageGenerator.Draw(rt, "message 2")

		w1, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		w2, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		c1, err := key.CommitWithWitness(m1, w1)
		require.NoError(t, err)

		c2, err := key.CommitWithWitness(m2, w2)
		require.NoError(t, err)

		m12, err := key.MessageOp(m1, m2)
		require.NoError(t, err)

		w12, err := key.WitnessOp(w1, w2)
		require.NoError(t, err)

		c12Expected, err := key.CommitWithWitness(m12, w12)
		require.NoError(t, err)

		c12Actual, err := key.CommitmentOp(c1, c2)
		require.NoError(t, err)

		require.True(t, c12Expected.Equal(c12Actual))

		err = key.Open(c12Actual, m12, w12)
		require.NoError(t, err)
	})
}

func (p *HomomorphicCommitmentKeyProperties[K, M, W, C, S]) CommitmentScalarOpIsMessageWitnessScalarOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")
		scalar := p.ScalarGenerator.Draw(rt, "scalar")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		messageScalar, err := key.MessageScalarOp(message, scalar)
		require.NoError(t, err)

		witnessScalar, err := key.WitnessScalarOp(witness, scalar)
		require.NoError(t, err)

		commitmentScalarExpected, err := key.CommitWithWitness(messageScalar, witnessScalar)
		require.NoError(t, err)

		commitmentScalarActual, err := key.CommitmentScalarOp(commitment, scalar)
		require.NoError(t, err)

		require.True(t, commitmentScalarExpected.Equal(commitmentScalarActual))
	})
}

func (p *HomomorphicCommitmentKeyProperties[K, M, W, C, S]) ReRandomiseShiftsWitness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		shift, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		rerandomised, err := key.ReRandomise(commitment, shift)
		require.NoError(t, err)

		combinedWitness, err := key.WitnessOp(witness, shift)
		require.NoError(t, err)

		err = key.Open(rerandomised, message, combinedWitness)
		require.NoError(t, err)
	})
}

func (p *HomomorphicCommitmentKeyProperties[K, M, W, C, S]) CanShiftCommitmentByMessage(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")
		shift := p.MessageGenerator.Draw(rt, "shift")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		shifted, err := key.Shift(commitment, shift)
		require.NoError(t, err)

		combinedMessage, err := key.MessageOp(message, shift)
		require.NoError(t, err)

		err = key.Open(shifted, combinedMessage, witness)
		require.NoError(t, err)
	})
}

func NewGroupHomomorphicCommitmentKeyProperties[
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
](
	tb testing.TB,
	prng func() io.Reader,
	keyGenerator *rapid.Generator[K],
	messageGenerator *MessageGenerator[M],
	messagesAreEqual func(M, M) bool,
	witnessesAreEqual func(W, W) bool,
	scalarGenerator *rapid.Generator[S],
	commitmentGenerator *rapid.Generator[C],
	newMessage func(MV) (M, error),
	newWitness func(WV) (W, error),
	newCommitment func(CV) (C, error),
) *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S] {
	tb.Helper()
	require.NotNil(tb, commitmentGenerator)
	require.NotNil(tb, newMessage)
	require.NotNil(tb, newWitness)
	require.NotNil(tb, newCommitment)
	return &GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]{
		HomomorphicCommitmentKeyProperties: *NewHomomorphicCommitmentKeyProperties(tb, prng, keyGenerator, messageGenerator, messagesAreEqual, witnessesAreEqual, scalarGenerator),
		CommitmentGenerator:                commitmentGenerator,
		NewMessage:                         newMessage,
		NewWitness:                         newWitness,
		NewCommitment:                      newCommitment,
	}
}

type GroupHomomorphicCommitmentKeyProperties[
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
] struct {
	HomomorphicCommitmentKeyProperties[K, M, W, C, S]

	CommitmentGenerator *rapid.Generator[C]

	NewMessage    func(MV) (M, error)
	NewWitness    func(WV) (W, error)
	NewCommitment func(CV) (C, error)
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("HomomorphicCommitmentKeyProperties", p.HomomorphicCommitmentKeyProperties.CheckAll)
	t.Run("CommitmentToZerosIsIdentity", p.CommitmentToZerosIsIdentity)
	t.Run("CommitmentInvIsMessageInvWitnessInv", p.CommitmentInvIsMessageInvWitnessInv)
	t.Run("WitnessOp", p.WitnessOp)
	t.Run("WitnessOpInv", p.WitnessOpInv)
	t.Run("MessageOp", p.MessageOp)
	t.Run("MessageOpInv", p.MessageOpInv)
	t.Run("CommitmentOp", p.CommitmentOp)
	t.Run("CommitmentOpInv", p.CommitmentOpInv)
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) CommitmentToZerosIsIdentity(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")

		zeroMessage, err := p.NewMessage(key.MessageGroup().OpIdentity())
		require.NoError(t, err)

		zeroWitness, err := p.NewWitness(key.WitnessGroup().OpIdentity())
		require.NoError(t, err)

		zeroCommitmentActual, err := key.CommitWithWitness(zeroMessage, zeroWitness)
		require.NoError(t, err)

		zeroCommitmentExpected, err := p.NewCommitment(key.CommitmentGroup().OpIdentity())
		require.NoError(t, err)

		require.True(t, zeroCommitmentActual.Equal(zeroCommitmentExpected))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) CommitmentInvIsMessageInvWitnessInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(t, err)

		messageInv, err := p.NewMessage(message.Value().OpInv())
		require.NoError(t, err)

		witnessInv, err := key.WitnessOpInv(witness)
		require.NoError(t, err)

		commitmentInvExpected, err := key.CommitWithWitness(messageInv, witnessInv)
		require.NoError(t, err)

		commitmentInvActual, err := key.CommitmentOpInv(commitment)
		require.NoError(t, err)

		require.True(t, commitmentInvExpected.Equal(commitmentInvActual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) WitnessOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		sampleCount := rapid.IntRange(2, 10).Draw(rt, "num samples")
		witnesses := make([]W, sampleCount)
		var err error
		for i := range sampleCount {
			witnesses[i], err = key.SampleWitness(p.PRNG())
			require.NoError(t, err)
		}
		actual, err := key.WitnessOp(witnesses[0], witnesses[1], witnesses[2:]...)
		require.NoError(t, err)

		expectedValue := witnesses[0].Value()
		for _, w := range witnesses[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := p.NewWitness(expectedValue)
		require.NoError(t, err)

		require.True(t, p.WitnessesAreEqual(expected, actual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) WitnessOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		witness, err := key.SampleWitness(p.PRNG())
		require.NoError(t, err)

		actual, err := key.WitnessOpInv(witness)
		require.NoError(t, err)

		expectedValue := witness.Value().OpInv()
		expected, err := p.NewWitness(expectedValue)
		require.NoError(t, err)

		require.True(t, p.WitnessesAreEqual(expected, actual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) MessageOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		messages := rapid.SliceOfN(p.MessageGenerator, 2, 10).Draw(rt, "messages")
		actual, err := key.MessageOp(messages[0], messages[1], messages[2:]...)
		require.NoError(t, err)

		expectedValue := messages[0].Value()
		for _, w := range messages[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := p.NewMessage(expectedValue)
		require.NoError(t, err)

		require.True(t, p.MessagesAreEqual(expected, actual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) MessageOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		message := p.MessageGenerator.Draw(rt, "message")

		actual, err := key.MessageOpInv(message)
		require.NoError(t, err)

		expectedValue := message.Value().OpInv()
		expected, err := p.NewMessage(expectedValue)
		require.NoError(t, err)

		require.True(t, p.MessagesAreEqual(expected, actual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) CommitmentOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		commitments := rapid.SliceOfN(p.CommitmentGenerator, 2, 10).Draw(rt, "commitments")
		actual, err := key.CommitmentOp(commitments[0], commitments[1], commitments[2:]...)
		require.NoError(t, err)

		expectedValue := commitments[0].Value()
		for _, w := range commitments[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := p.NewCommitment(expectedValue)
		require.NoError(t, err)

		require.True(t, expected.Equal(actual))
	})
}

func (p *GroupHomomorphicCommitmentKeyProperties[K, M, MG, MV, W, WG, WV, C, CG, CV, S]) CommitmentOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		key := p.KeyGenerator.Draw(rt, "commitment key")
		commitment := p.CommitmentGenerator.Draw(rt, "commitment")

		actual, err := key.CommitmentOpInv(commitment)
		require.NoError(t, err)

		expectedValue := commitment.Value().OpInv()
		expected, err := p.NewCommitment(expectedValue)
		require.NoError(t, err)

		require.True(t, expected.Equal(actual))
	})
}

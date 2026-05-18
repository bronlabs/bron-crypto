package hashcom_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"pgregory.net/rapid"
)

func CommitmentKeyGenerator() *rapid.Generator[*hashcom.CommitmentKey] {
	return rapid.Custom(func(t *rapid.T) *hashcom.CommitmentKey {
		b := rapid.SliceOfN(rapid.Byte(), hashcom.KeySize, hashcom.KeySize).Draw(t, "commitment key bytes")
		var out hashcom.CommitmentKey
		copy(out[:], b)
		return &out
	})
}

func CommitmentGenerator(tb testing.TB, _ commitments.CommitmentKey[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment]) *rapid.Generator[hashcom.Commitment] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hashcom.Commitment {
		b := rapid.SliceOfN(rapid.Byte(), hashcom.DigestSize, hashcom.DigestSize).Draw(t, "commitment bytes")
		var out hashcom.Commitment
		copy(out[:], b)
		return out
	})
}

func MessageGenerator(tb testing.TB, _ commitments.CommitmentKey[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment]) *rapid.Generator[hashcom.Message] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hashcom.Message {
		return hashcom.Message(rapid.SliceOfN(rapid.Byte(), 0, 32).Draw(t, "message bytes"))
	})
}

func WitnessGenerator(tb testing.TB, _ commitments.CommitmentKey[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment]) *rapid.Generator[hashcom.Witness] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hashcom.Witness {
		b := rapid.SliceOfN(rapid.Byte(), hashcom.DigestSize, hashcom.DigestSize).Draw(t, "witness bytes")
		var out hashcom.Witness
		copy(out[:], b)
		return out
	})
}

func CommitmentKeyPropertySuite(tb testing.TB) *properties.CommitmentKeyProperties[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment] {
	tb.Helper()
	return &properties.CommitmentKeyProperties[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment]{
		PRNG:             prng.PRNGFuncTypeErase(pcg.NewRandomised),
		KeyGenerator:     CommitmentKeyGenerator(),
		MessageGenerator: MessageGenerator,
		MessagesAreEqual: func(m1, m2 hashcom.Message) bool {
			return bytes.Equal(m1, m2)
		},
		WitnessesAreEqual: func(w1, w2 hashcom.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func WitnessPropertySuite(tb testing.TB) *properties.WitnessProperties[hashcom.Witness] {
	tb.Helper()
	return &properties.WitnessProperties[hashcom.Witness]{
		WitnessGenerator: WitnessGenerator(tb, nil),
		WitnessesAreEqual: func(w1, w2 hashcom.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func MessagePropertySuite(tb testing.TB) *properties.MessageProperties[hashcom.Message] {
	tb.Helper()
	return &properties.MessageProperties[hashcom.Message]{
		MessageGenerator: MessageGenerator(tb, nil),
		MessagesAreEqual: func(m1, m2 hashcom.Message) bool {
			return bytes.Equal(m1, m2)
		},
	}
}

func CommitmentPropertySuite(tb testing.TB) *properties.CommitmentProperties[hashcom.Commitment] {
	tb.Helper()
	return &properties.CommitmentProperties[hashcom.Commitment]{
		CommitmentGenerator: CommitmentGenerator(tb, nil),
		CommitmentsAreEqual: func(c1, c2 hashcom.Commitment) bool {
			return bytes.Equal(c1[:], c2[:])
		},
	}
}

func TestCommitmentKeyProperties(t *testing.T) {
	CommitmentKeyPropertySuite(t).CheckAll(t)
}

func TestWitnessProperties(t *testing.T) {
	WitnessPropertySuite(t).CheckAll(t)
}

func TestMessageProperties(t *testing.T) {
	MessagePropertySuite(t).CheckAll(t)
}

func TestCommitmentProperties(t *testing.T) {
	CommitmentPropertySuite(t).CheckAll(t)
}

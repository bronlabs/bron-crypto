package commitments

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type (
	Commitment []byte
	Witness    []byte
)

func Commit(sessionId []byte, prng io.Reader, messages ...[]byte) (Commitment, Witness, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	if len(sessionId) == 0 {
		return nil, nil, errs.NewArgument("sessionId is empty/nil")
	}
	if len(messages) == 0 {
		return nil, nil, errs.NewArgument("no commit message")
	}

	msgs := slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytesLE(len(sessionId)), sessionId)
	for i, m := range messages {
		msgs = slices.Concat(msgs, bitstring.ToBytesLE(i), bitstring.ToBytesLE(len(m)), m)
	}

	return commitInternal(prng, msgs)
}

func Open(sessionId []byte, commitment Commitment, witness Witness, messages ...[]byte) error {
	msgs := slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytesLE(len(sessionId)), sessionId)
	for i, m := range messages {
		msgs = slices.Concat(msgs, bitstring.ToBytesLE(i), bitstring.ToBytesLE(len(m)), m)
	}

	return openInternal(commitment, witness, msgs)
}

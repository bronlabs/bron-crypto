package commitments

import (
	"io"

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

	return commitInternal(prng, encodeWithSessionId(sessionId, messages...)...)
}

func Open(sessionId []byte, commitment Commitment, witness Witness, messages ...[]byte) error {
	return openInternal(commitment, witness, encodeWithSessionId(sessionId, messages...)...)
}

func CommitWithoutSession(prng io.Reader, messages ...[]byte) (Commitment, Witness, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	if len(messages) == 0 {
		return nil, nil, errs.NewArgument("no commit message")
	}
	return commitInternal(prng, encode(messages...)...)
}

func OpenWithoutSession(commitment Commitment, witness Witness, messages ...[]byte) error {
	return openInternal(commitment, witness, encode(messages...)...)
}

package dkg

import (
	"maps"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	nLabel = "BRON_CRYPTO_TRSA_DKG-CD-N-"
	eLabel = "BRON_CRYPTO_TRSA_DKG-CD-E-"
)

func proveCD(tape transcripts.Transcript, shares map[types.SharingID]*rep23.IntShare, n *saferith.Modulus) (map[types.SharingID]*rep23.IntExpShare, error) {
	challenge, err := deriveChallenge(tape, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive challenge")
	}
	sharesInExp := make(map[types.SharingID]*rep23.IntExpShare)
	for sid, share := range shares {
		sharesInExp[sid] = share.InExponent(challenge, n)
	}
	return sharesInExp, nil
}

func verifyCD(tape transcripts.Transcript, proof map[types.SharingID]*rep23.IntExpShare, n *saferith.Modulus, share *rep23.IntShare) error {
	challenge, err := deriveChallenge(tape, n)
	if err != nil {
		return errs.WrapFailed(err, "cannot derive challenge")
	}

	dealer := rep23.NewIntExpScheme(n)
	s, err := dealer.Open(slices.Collect(maps.Values(proof))...)
	if err != nil {
		return errs.WrapValidation(err, "invalid shares")
	}
	c := new(saferith.Nat).Exp(s, new(saferith.Nat).SetUint64(trsa.RsaE), n)
	if challenge.Eq(c) == 0 {
		return errs.NewValidation("invalid shares")
	}

	shareInExp := share.InExponent(challenge, n)
	shareInExpCheck, ok := proof[share.SharingId()]
	if !ok {
		return errs.NewValidation("invalid shares")
	}
	if !shareInExp.Equal(shareInExpCheck) {
		return errs.NewValidation("invalid shares")
	}

	return nil
}

func deriveChallenge(tape transcripts.Transcript, n *saferith.Modulus) (*saferith.Nat, error) {
	piTape := tape.Clone()
	piTape.AppendMessages(nLabel, n.Bytes())
	eBytes, err := piTape.ExtractBytes(eLabel, trsa.RsaBitLen/8)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extract challenge")
	}
	e := new(saferith.Nat).SetBytes(eBytes)
	e.Mod(e, n)
	return e, nil
}

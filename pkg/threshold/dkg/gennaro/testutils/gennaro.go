package testutils

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func MakeGennaroParticipants[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](sessionId []byte, protocol types.ThresholdProtocol[C, P, F, S], identities []types.IdentityKey, tapes []transcripts.Transcript, prngs []io.Reader) (participants []*gennaro.Participant[C, P, F, S], err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*gennaro.Participant[C, P, F, S], protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not a participant (problem in tests?)")
		}

		participants[i], err = gennaro.NewParticipant(sessionId, identity.(types.AuthKey), protocol, tapes[i], prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoGennaroRound1[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](participants []*gennaro.Participant[C, P, F, S]) (round1BroadcastOutputs []*gennaro.Round1Broadcast[P, F, S], err error) {
	round1BroadcastOutputs = make([]*gennaro.Round1Broadcast[P, F, S], len(participants))
	for i := range participants {
		round1BroadcastOutputs[i], err = participants[i].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "%s could not run Gennaro round 1", participants[i].IdentityKey().String())
		}
	}

	return round1BroadcastOutputs, nil
}

func DoGennaroRound2[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](participants []*gennaro.Participant[C, P, F, S], round2BroadcastInputs []network.RoundMessages[*gennaro.Round1Broadcast[P, F, S]]) (round2BroadcastOutputs []*gennaro.Round2Broadcast[P, F, S], round2UnicastOutputs []network.RoundMessages[*gennaro.Round2P2P[S]], err error) {
	round2BroadcastOutputs = make([]*gennaro.Round2Broadcast[P, F, S], len(participants))
	round2UnicastOutputs = make([]network.RoundMessages[*gennaro.Round2P2P[S]], len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run Gennaro round 2", participants[i].IdentityKey().String())
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func DoGennaroRound3[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](participants []*gennaro.Participant[C, P, F, S], round3BroadcastInputs []network.RoundMessages[*gennaro.Round2Broadcast[P, F, S]], round3UnicastInputs []network.RoundMessages[*gennaro.Round2P2P[S]]) (signingKeyShares []*tsignatures.SigningKeyShare[C, P, F, S], publicKeyShares []*tsignatures.PartialPublicKeys[C, P, F, S], err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare[C, P, F, S], len(participants))
	publicKeyShares = make([]*tsignatures.PartialPublicKeys[C, P, F, S], len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run Gennaro round 3", participants[i].IdentityKey().String())
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func DoGennaroDkg[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, sessionId []byte, protocol types.ThresholdProtocol[C, P, F, S], identities []types.IdentityKey, tapes []transcripts.Transcript) (signingKeyShares []*tsignatures.SigningKeyShare[C, P, F, S], publicKeyShares []*tsignatures.PartialPublicKeys[C, P, F, S], err error) {
	tb.Helper()

	participants, err := MakeGennaroParticipants(sessionId, protocol, identities, tapes, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, err := DoGennaroRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB := ttu.MapBroadcastO2I(tb, participants, r1OutsB)
	r2OutsB, r2OutsU, err := DoGennaroRound2(participants, r2InsB)
	if err != nil {
		return nil, nil, err
	}

	r3InsB, r3InsU := ttu.MapO2I(tb, participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err = DoGennaroRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}

func DoDkgHappyPath[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, sessionId []byte, protocol types.ThresholdProtocol[C, P, F, S], identities []types.IdentityKey, tapes []transcripts.Transcript) (signingKeyShares []*tsignatures.SigningKeyShare[C, P, F, S], publicKeyShares []*tsignatures.PartialPublicKeys[C, P, F, S]) {
	tb.Helper()

	signingKeyShares, publicKeyShares, err := DoGennaroDkg(tb, sessionId, protocol, identities, tapes)
	require.NoError(tb, err)
	return signingKeyShares, publicKeyShares
}

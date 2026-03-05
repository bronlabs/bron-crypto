package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	gentu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/keygen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	dlogschnorr "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// DoLindell22DKG runs a complete DKG process and returns Lindell22 shards.
func DoLindell22DKG[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](tb testing.TB, participants map[sharing.ID]*gennaro.Participant[GE, S]) (shards map[sharing.ID]*lindell22.Shard[GE, S]) {
	tb.Helper()

	// Run Gennaro DKG
	dkgOutputs := gentu.DoGennaroDKG(tb, participants)
	shards = make(map[sharing.ID]*lindell22.Shard[GE, S])
	for id, output := range dkgOutputs {
		shard, err := keygen.NewShard(output)
		require.NoError(tb, err)
		shards[id] = shard
	}
	return shards
}

// CreateLindell22Cosigners creates a set of cosigners for testing.
func CreateLindell22Cosigners[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message](
	tb testing.TB,
	ctxs map[sharing.ID]*session.Context,
	shards map[sharing.ID]*lindell22.Shard[GE, S],
	variant tschnorr.MPCFriendlyVariant[GE, S, M],
	prng io.Reader,
) map[sharing.ID]*signing.Cosigner[GE, S, M] {
	tb.Helper()

	cosigners := make(map[sharing.ID]*signing.Cosigner[GE, S, M])
	var group algebra.PrimeGroup[GE, S]

	for id, ctx := range ctxs {
		shard := ntu.CBORRoundTrip(tb, shards[id])
		if group == nil {
			group = shard.PublicKey().Group()
		}

		niCompilerName := fiatshamir.Name
		cosigner, err := signing.NewCosigner(ctx, shard, niCompilerName, variant, prng)
		require.NoError(tb, err)
		cosigners[id] = cosigner
	}

	return cosigners
}

func DoLindell22Round1[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message](tb testing.TB, participants map[sharing.ID]*signing.Cosigner[E, S, M]) map[sharing.ID]*signing.Round1Broadcast {
	tb.Helper()
	r1bo := make(map[sharing.ID]*signing.Round1Broadcast, len(participants))
	for id, pi := range participants {
		v, err := pi.Round1()
		require.NoError(tb, err)
		r1bo[id] = v
	}

	return r1bo
}

func DoLindell22Round2[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message](tb testing.TB, participants map[sharing.ID]*signing.Cosigner[E, S, M], r2bi map[sharing.ID]network.RoundMessages[*signing.Round1Broadcast]) map[sharing.ID]*signing.Round2Broadcast[E, S] {
	tb.Helper()
	r2bo := make(map[sharing.ID]*signing.Round2Broadcast[E, S], len(participants))
	for id, pi := range participants {
		v, err := pi.Round2(r2bi[id])
		require.NoError(tb, err)
		r2bo[id] = v
	}
	return r2bo
}

func DoLindell22Round3[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message](tb testing.TB, participants map[sharing.ID]*signing.Cosigner[E, S, M], r3bi map[sharing.ID]network.RoundMessages[*signing.Round2Broadcast[E, S]], message M) map[sharing.ID]*lindell22.PartialSignature[E, S] {
	tb.Helper()
	psigs := make(map[sharing.ID]*lindell22.PartialSignature[E, S])
	for id, pi := range participants {
		v, err := pi.Round3(r3bi[pi.SharingID()], message)
		require.NoError(tb, err)
		psigs[id] = v
	}
	return psigs
}

// CreateCorruptedPartialSignature creates an invalid partial signature for testing.
func CreateCorruptedPartialSignature[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	tb testing.TB,
	validPsig *lindell22.PartialSignature[GE, S],
) *lindell22.PartialSignature[GE, S] {
	tb.Helper()

	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](validPsig.Sig.S.Structure())
	// Corrupt the S value by adding 1
	corruptedS := validPsig.Sig.S.Add(sf.One())

	return &lindell22.PartialSignature[GE, S]{
		Sig: schnorrlike.Signature[GE, S]{
			E: validPsig.Sig.E,
			R: validPsig.Sig.R,
			S: corruptedS,
		},
	}
}

// NewFiatShamirCompiler creates a new Fiat-Shamir compiler for the given protocol.
func NewFiatShamirCompiler[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	protocol *dlogschnorr.Protocol[GE, S],
) (compiler.NonInteractiveProtocol[*dlogschnorr.Statement[GE, S], *dlogschnorr.Witness[S]], error) {
	return fiatshamir.NewCompiler(protocol)
}

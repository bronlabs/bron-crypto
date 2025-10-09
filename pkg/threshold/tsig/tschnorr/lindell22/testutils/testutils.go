package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	dlogschnorr "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	gentu "github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/keygen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/signing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/stretchr/testify/require"
)

// DoLindell22DKG runs a complete DKG process and returns Lindell22 shards
func DoLindell22DKG[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	tb *testing.T,
	participants []*gennaro.Participant[GE, S],
) (shards ds.MutableMap[sharing.ID, *lindell22.Shard[GE, S]], err error) {
	tb.Helper()

	// Run Gennaro DKG
	dkgOutputs, err := gentu.DoGennaroDKG(tb, participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run Gennaro DKG")
	}
	shards = hashmap.NewComparable[sharing.ID, *lindell22.Shard[GE, S]]()
	for id, output := range dkgOutputs.Iter() {
		shard, err := keygen.NewShard(output)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create shard for participant %d", id)
		}
		shards.Put(id, shard)
	}
	return shards, nil
}

// CreateLindell22Cosigners creates a set of cosigners for testing
func CreateLindell22Cosigners[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](
	t *testing.T,
	signingSID network.SID,
	shards map[sharing.ID]*lindell22.Shard[GE, S],
	quorum network.Quorum,
	variant tschnorr.MPCFriendlyVariant[GE, S, M],
	newCompilerMaker func(protocol *dlogschnorr.Protocol[GE, S]) (compiler.NICompiler[*dlogschnorr.Statement[GE, S], *dlogschnorr.Witness[S]], error),
	transcript ts.Transcript,
	prng io.Reader,
) []*signing.Cosigner[GE, S, M] {
	t.Helper()

	cosigners := make([]*signing.Cosigner[GE, S, M], 0, quorum.Size())
	var group algebra.PrimeGroup[GE, S]

	for id := range quorum.Iter() {
		shard := shards[id]
		if group == nil {
			group = shard.PublicKey().Group()
		}

		dlogProtocol, err := dlogschnorr.NewSigmaProtocol(group.Generator(), prng)
		require.NoError(t, err)
		schnorrDlogProtocol, ok := dlogProtocol.(*dlogschnorr.Protocol[GE, S])
		require.True(t, ok)
		niDlogScheme, err := newCompilerMaker(schnorrDlogProtocol)
		require.NoError(t, err)

		cosigner, err := signing.NewCosigner[
			GE, S, M,
		](
			signingSID,
			testutils.CBORRoundTrip(t, shard),
			quorum,
			group,
			niDlogScheme,
			variant,
			prng,
			transcript.Clone(),
		)
		require.NoError(t, err)
		cosigners = append(cosigners, cosigner)
	}

	return cosigners
}

func DoLindell22Round1[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
	M schnorrlike.Message,
](
	participants []*signing.Cosigner[E, S, M],
) (
	r1bo map[sharing.ID]*signing.Round1Broadcast, err error,
) {
	r1bo = make(map[sharing.ID]*signing.Round1Broadcast, len(participants))
	for _, pi := range participants {
		r1bo[pi.SharingID()], err = pi.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "%d could not run lindell22 signing round 1", pi.SharingID())
		}
	}

	return r1bo, nil
}

func DoLindell22Round2[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
	M schnorrlike.Message,
](
	participants []*signing.Cosigner[E, S, M], r2bi map[sharing.ID]network.RoundMessages[*signing.Round1Broadcast],
) (
	r2bo map[sharing.ID]*signing.Round2Broadcast[E, S], err error,
) {
	r2bo = make(map[sharing.ID]*signing.Round2Broadcast[E, S], len(participants))
	for _, pi := range participants {
		r2bo[pi.SharingID()], err = pi.Round2(r2bi[pi.SharingID()])
		if err != nil {
			return nil, errs.WrapFailed(err, "%d could not run lindell22 signing round 2", pi.SharingID())
		}
	}
	return r2bo, nil
}

func DoLindell22Round3[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
	M schnorrlike.Message,
](
	participants []*signing.Cosigner[E, S, M], r3bi map[sharing.ID]network.RoundMessages[*signing.Round2Broadcast[E, S]],
	message M,
) (
	psigs ds.MutableMap[sharing.ID, *lindell22.PartialSignature[E, S]], err error,
) {
	psigs = hashmap.NewComparable[sharing.ID, *lindell22.PartialSignature[E, S]]()
	for _, pi := range participants {
		v, err := pi.Round3(r3bi[pi.SharingID()], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "%d could not run Gennaro round 3", pi.SharingID())
		}
		psigs.Put(pi.SharingID(), v)
	}
	return psigs, nil
}

// CreateCorruptedPartialSignature creates an invalid partial signature for testing
func CreateCorruptedPartialSignature[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	t *testing.T,
	validPsig *lindell22.PartialSignature[GE, S],
	sf algebra.PrimeField[S],
) *lindell22.PartialSignature[GE, S] {
	t.Helper()

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

// NewFiatShamirCompiler creates a new Fiat-Shamir compiler for the given protocol
func NewFiatShamirCompiler[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	protocol *dlogschnorr.Protocol[GE, S],
) (compiler.NICompiler[*dlogschnorr.Statement[GE, S], *dlogschnorr.Witness[S]], error) {
	return fiatshamir.NewCompiler(protocol)
}

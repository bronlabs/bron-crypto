package gennaro

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/okamoto"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
	"github.com/bronlabs/errs-go/errs"
)

const (
	batchOkamotoProverIDLabel = "BRON_CRYPTO_DKG_GENNARO_BATCH_OKAMOTO_PROVER_ID-"
	batchSchnorrProverIDLabel = "BRON_CRYPTO_DKG_GENNARO_BATCH_SCHNORR_PROVER_ID-"
)

func (p *Participant[E, S]) Round1() (*Round1Broadcast[E, S], network.OutgoingUnicasts[*Round1Unicast[E, S], *Participant[E, S]], error) {
	if p.round != 1 {
		return nil, nil, ErrRound.WithMessage("expected round 1, got %d", p.round)
	}
	// Pedersen VSS dealing
	var err error
	p.state.localPedersenDealerOutput, _, p.state.pedersenDealerFunc, err = p.state.pedersenVSS.DealRandomAndRevealDealerFunc(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal random and reveal dealer function")
	}
	secretsColumnVector, blindingColumnVector := p.state.pedersenDealerFunc.G(), p.state.pedersenDealerFunc.H()
	pedersenVerificationVector := p.state.localPedersenDealerOutput.VerificationMaterial()

	// My own local share
	var ok bool
	p.state.localShare, ok = p.state.localPedersenDealerOutput.Shares().Get(p.ctx.HolderID())
	if !ok {
		return nil, nil, ErrFailed.WithMessage("failed to get my pedersen share")
	}

	// Other people's shares
	r1uo := hashmap.NewComparable[sharing.ID, *Round1Unicast[E, S]]()
	for pid := range p.ctx.OtherPartiesOrdered() {
		shareForThisParty, exists := p.state.localPedersenDealerOutput.Shares().Get(pid)
		if !exists {
			return nil, nil, ErrFailed.WithMessage("missing pedersen share for party %d", pid)
		}
		r1uo.Put(pid, &Round1Unicast[E, S]{
			Share: shareForThisParty,
		})
	}

	// Proof of knowledge of opening
	okamotoProtocol, err := okamoto.NewProtocol([]E{p.state.key.G(), p.state.key.H()}, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto protocol")
	}
	batchOkamotoProtocol, err := sigand.Compose(okamotoProtocol, p.state.lsss.MSP().D())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to compose okamoto protocol")
	}
	niBatchOkamoto, err := compiler.Compile(p.niCompilerName, batchOkamotoProtocol, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to compile okamoto protocol to non-interactive")
	}
	proverCtx := p.ctx.Clone()
	proverCtx.Transcript().AppendBytes(batchOkamotoProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.ctx.HolderID())))
	prover, err := niBatchOkamoto.NewProver(proverCtx)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto prover")
	}
	secretsColumnVectorElements := slices.Collect(secretsColumnVector.RandomColumn().Iter())
	blindingColumnVectorElements := slices.Collect(blindingColumnVector.RandomColumn().Iter())
	pedersenVerificationVectorElements := slices.Collect(pedersenVerificationVector.Value().Iter())
	witnesses := make([]*okamoto.Witness[S], len(secretsColumnVectorElements))
	statements := make([]*okamoto.Statement[E, S], len(secretsColumnVectorElements))
	for i, ci := range secretsColumnVectorElements {
		bi := blindingColumnVectorElements[i]
		witnesses[i], err = okamoto.NewWitness(ci, bi)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto witness for coefficient %d", i)
		}
		statements[i] = okamoto.NewStatement(pedersenVerificationVectorElements[i])
	}
	witness := sigand.ComposeWitnesses(witnesses...)
	statement := sigand.ComposeStatements(statements...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto proof")
	}

	p.round++
	return &Round1Broadcast[E, S]{
		PedersenVerificationVector: pedersenVerificationVector,
		Proof:                      proof,
	}, r1uo.Freeze(), nil
}

func (p *Participant[E, S]) Round2(r2bin network.RoundMessages[*Round1Broadcast[E, S], *Participant[E, S]], r2uin network.RoundMessages[*Round1Unicast[E, S], *Participant[E, S]]) (*Round2Broadcast[E, S], error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage("expected round 2, got %d", p.round)
	}

	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2bin); errB != nil {
		return nil, errs.Wrap(errB)
	}
	if errU := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2uin); errU != nil {
		return nil, errs.Wrap(errU)
	}

	localSecretColumnVector := p.state.pedersenDealerFunc.G()

	var err error
	p.state.summedShareValue = p.state.localShare.Value()
	for pid := range p.ctx.OtherPartiesOrdered() {
		inB, _ := r2bin.Get(pid)
		inU, _ := r2uin.Get(pid)

		// Verify Okamoto proof of knowledge of opening
		okamotoProtocol, err := okamoto.NewProtocol([]E{p.state.key.G(), p.state.key.H()}, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create okamoto protocol")
		}
		batchOkamotoProtocol, err := sigand.Compose(okamotoProtocol, p.state.lsss.MSP().D())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compose okamoto protocol")
		}
		niBatchOkamoto, err := compiler.Compile(p.niCompilerName, batchOkamotoProtocol, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compile okamoto protocol to non-interactive")
		}
		verifierCtx := p.ctx.Clone()
		verifierCtx.Transcript().AppendBytes(batchOkamotoProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchOkamoto.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create okamoto verifier")
		}
		if err := verifier.Verify(
			sigand.ComposeStatements(slices.Collect(iterutils.Map(inB.PedersenVerificationVector.Value().Iter(), okamoto.NewStatement))...),
			inB.Proof,
		); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify okamoto proof of knowledge of opening from party %d", pid)
		}

		// Verify Share
		if err := p.state.pedersenVSS.Verify(inU.Share, inB.PedersenVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify pedersen share from party %d", pid)
		}
		p.state.receivedShares[pid] = inU.Share

		// Accumulate shares for final key material
		if len(p.state.summedShareValue) != len(inU.Share.Value()) {
			return nil, errs.New("inconsistent share value length").WithTag(base.IdentifiableAbortPartyIDTag, pid)
		}
		for i, v := range inU.Share.Value() {
			p.state.summedShareValue[i] = p.state.summedShareValue[i].Add(v)
		}
	}

	// Produce Feldman verification vector for the same column vector.
	liftedRandomColumn, err := mat.Lift(localSecretColumnVector.RandomColumn(), p.state.key.G())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift pedersen dealer function to exponent")
	}
	p.state.localFeldmanVerificationVector, err = feldman.NewVerificationVector(liftedRandomColumn, p.state.lsss.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create feldman verification vector from lifted random column")
	}

	// Produce batch schnorr proof of knowledge of Feldman verification vector's coefficients' dlog.
	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.state.lsss.MSP().D()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}
	proverCtx := p.ctx.Clone()
	proverCtx.Transcript().AppendBytes(batchSchnorrProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.ctx.HolderID())))
	prover, err := niBatchSchnorr.NewProver(proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
	}

	witness := batch_schnorr.NewWitness(slices.Collect(localSecretColumnVector.RandomColumn().Iter())...)
	statement := batch_schnorr.NewStatement(p.state.key.G(), slices.Collect(p.state.localFeldmanVerificationVector.Value().Iter())...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove batch schnorr statement")
	}

	p.round++
	return &Round2Broadcast[E, S]{
		FeldmanVerificationVector: p.state.localFeldmanVerificationVector,
		Proof:                     proof,
	}, nil
}

func (p *Participant[E, S]) Round3(r3bi network.RoundMessages[*Round2Broadcast[E, S], *Participant[E, S]]) (*mpc.BaseShard[E, S], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("expected round 3, got %d", p.round)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r3bi); errB != nil {
		return nil, errs.Wrap(errB)
	}

	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.state.lsss.MSP().D()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}

	summedFeldmanVerificationVector := p.state.localFeldmanVerificationVector
	for pid := range p.ctx.OtherPartiesOrdered() {
		inB, _ := r3bi.Get(pid)

		// Verify batch schnorr proof of knowledge of Feldman verification vector's coefficients' dlog.
		verifierCtx := p.ctx.Clone()
		verifierCtx.Transcript().AppendBytes(batchSchnorrProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchSchnorr.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
		}
		statement := batch_schnorr.NewStatement(p.state.key.G(), slices.Collect(inB.FeldmanVerificationVector.Value().Iter())...)
		err = verifier.Verify(statement, inB.Proof)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman verification vector")
		}

		// Verify Feldman Share
		kwShare, err := kw.NewShare(p.state.receivedShares[pid].ID(), p.state.receivedShares[pid].Value()...)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to convert received share to kw share for verification")
		}
		if err := p.state.feldmanVSS.Verify(kwShare, inB.FeldmanVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman share from party %d", pid)
		}

		// Accumulate Feldman verification vectors for final output
		summedFeldmanVerificationVector, err = summedFeldmanVerificationVector.Op(inB.FeldmanVerificationVector)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to accumulate feldman verification vector from party %d", pid)
		}
	}
	outputShare, err := kw.NewShare(p.ctx.HolderID(), p.state.summedShareValue...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create output feldman share")
	}
	out, err := mpc.NewBaseShard(outputShare, summedFeldmanVerificationVector, p.state.lsss.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create DKG output")
	}
	p.round++
	return out, nil
}

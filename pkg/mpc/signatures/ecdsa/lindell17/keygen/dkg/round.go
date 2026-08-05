package dkg

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

const (
	transcriptDLogSLabel            = "BRON_CRYPTO_LINDELL17_DKG_DLOG-"
	dlogProverLabel                 = "BRON_CRYPTO_LINDELL17_DKG_DLOG_PROVER-"
	dlogRowLabel                    = "BRON_CRYPTO_LINDELL17_DKG_DLOG_ROW-"
	dlogHalfLabel                   = "BRON_CRYPTO_LINDELL17_DKG_DLOG_HALF-"
	dlogPointLabel                  = "BRON_CRYPTO_LINDELL17_DKG_DLOG_POINT-"
	bigQTwinLabel                   = "BRON_CRYPTO_LINDELL17_DKG_BIG_Q_TWIN-"
	pairProverLabel                 = "BRON_CRYPTO_LINDELL17_DKG_PAIR_PROVER-"
	pairVerifierLabel               = "BRON_CRYPTO_LINDELL17_DKG_PAIR_VERIFIER-"
	pairProofKindLabel              = "BRON_CRYPTO_LINDELL17_DKG_PAIR_PROOF_KIND-"
	pairPaillierKeyLabel            = "BRON_CRYPTO_LINDELL17_DKG_PAIR_PAILLIER_KEY-"
	pairRowLabel                    = "BRON_CRYPTO_LINDELL17_DKG_PAIR_ROW-"
	pairPointLabel                  = "BRON_CRYPTO_LINDELL17_DKG_PAIR_POINT-"
	pairCiphertextLabel             = "BRON_CRYPTO_LINDELL17_DKG_PAIR_CIPHERTEXT-"
	invalidRoundMessage             = "running round %d but participant expected round %d"
	dlogPrimeHalf            uint64 = 1
	dlogDoublePrimeHalf      uint64 = 2
	pairProofLP                     = "LP"
	pairProofLPDLPrime              = "LPDL_PRIME"
	pairProofLPDLDoublePrime        = "LPDL_DOUBLE_PRIME"
)

// Round1 decomposes every component of the local raw MSP share and commits to
// the row-indexed point pairs.
func (p *Participant[P, B, S]) Round1() (*Round1Broadcast[P, B, S], error) {
	if p.round != 1 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 1, p.round)
	}

	rows := p.shareRows(p.SharingID())
	shareValues := p.baseShard.Share().Value()
	if len(shareValues) != len(rows) {
		return nil, ErrInvalidArgument.WithMessage("local MSP share component count does not match its row count")
	}
	components := make([]*ComponentDecomposition[P, B, S], len(rows))
	for i, row := range rows {
		xPrime, xDoublePrime, err := lindell17.DecomposeTwoThirds(shareValues[i], p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot split raw share component for MSP row %d", row)
		}
		bigQPrime := p.curve.ScalarBaseMul(xPrime)
		bigQDoublePrime := p.curve.ScalarBaseMul(xDoublePrime)

		p.state.myXPrime[i] = xPrime
		p.state.myXDoublePrime[i] = xDoublePrime
		p.state.myBigQPrime[i] = bigQPrime
		p.state.myBigQDoublePrime[i] = bigQDoublePrime
		components[i] = &ComponentDecomposition[P, B, S]{
			Row:                  row,
			BigQPrime:            bigQPrime,
			BigQPrimeProof:       nil,
			BigQDoublePrime:      bigQDoublePrime,
			BigQDoublePrimeProof: nil,
		}
	}

	bigQCommitment, bigQOpening, err := commitments.Commit(
		p.state.commitmentKeys[p.SharingID()],
		encodeComponentPoints(components),
		p.prng,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot commit to decomposed raw-share component points")
	}

	p.state.myBigQOpening = bigQOpening
	p.round++
	return &Round1Broadcast[P, B, S]{BigQCommitment: bigQCommitment}, nil
}

// Round2 records the other commitments and opens this participant's commitment
// together with row-bound discrete-log proofs for every decomposition half.
func (p *Participant[P, B, S]) Round2(input network.RoundMessages[*Round1Broadcast[P, B, S], *Participant[P, B, S]]) (*Round2Broadcast[P, B, S], error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 2, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-1 messages")
	}
	for id := range p.ctx.OtherPartiesOrdered() {
		message, _ := input.Get(id)
		p.state.theirBigQCommitment[id] = message.BigQCommitment
	}

	rows := p.shareRows(p.SharingID())
	components := make([]*ComponentDecomposition[P, B, S], len(rows))
	for i, row := range rows {
		primeProof, err := dlogProve(
			p,
			p.state.myBigQPrime[i],
			p.state.myBigQDoublePrime[i],
			p.state.myXPrime[i],
			row,
			dlogPrimeHalf,
		)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create Q' discrete-log proof for MSP row %d", row)
		}
		doublePrimeProof, err := dlogProve(
			p,
			p.state.myBigQDoublePrime[i],
			p.state.myBigQPrime[i],
			p.state.myXDoublePrime[i],
			row,
			dlogDoublePrimeHalf,
		)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create Q'' discrete-log proof for MSP row %d", row)
		}
		components[i] = &ComponentDecomposition[P, B, S]{
			Row:                  row,
			BigQPrime:            p.state.myBigQPrime[i],
			BigQPrimeProof:       primeProof,
			BigQDoublePrime:      p.state.myBigQDoublePrime[i],
			BigQDoublePrimeProof: doublePrimeProof,
		}
	}

	p.round++
	return &Round2Broadcast[P, B, S]{
		BigQOpening: p.state.myBigQOpening,
		Components:  components,
	}, nil
}

// Round3 verifies every raw-share component decomposition, samples one
// Paillier key, encrypts every local decomposition half once, and initialises
// peer-bound LP and component-wise LPDL prover states.
func (p *Participant[P, B, S]) Round3(input network.RoundMessages[*Round2Broadcast[P, B, S], *Participant[P, B, S]]) (*Round3Broadcast[P, B, S], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 3, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-2 messages")
	}

	for id := range p.ctx.OtherPartiesOrdered() {
		message, _ := input.Get(id)
		if err := p.state.commitmentKeys[id].Open(
			p.state.theirBigQCommitment[id],
			encodeComponentPoints(message.Components),
			message.BigQOpening,
		); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot open decomposed raw-share component commitment")
		}

		publicShare, ok := p.baseShard.PublicKeyShares().Get(id)
		if !ok || publicShare == nil {
			return nil, ErrMissing.WithMessage("could not find public key share for participant %d", id)
		}
		if len(publicShare.Value()) != len(message.Components) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("decomposition count does not match public MSP share")
		}

		primePoints := make([]P, len(message.Components))
		doublePrimePoints := make([]P, len(message.Components))
		for i, component := range message.Components {
			if err := dlogVerify(p, id, component.BigQPrimeProof, component.BigQPrime, component.BigQDoublePrime, component.Row, dlogPrimeHalf); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify Q' discrete-log proof for MSP row %d", component.Row)
			}
			if err := dlogVerify(p, id, component.BigQDoublePrimeProof, component.BigQDoublePrime, component.BigQPrime, component.Row, dlogDoublePrimeHalf); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify Q'' discrete-log proof for MSP row %d", component.Row)
			}

			actualPoint := triplePoint(component.BigQPrime).Add(component.BigQDoublePrime)
			if !actualPoint.Equal(publicShare.Value()[i]) {
				return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("decomposition does not match public MSP share component at row %d", component.Row)
			}
			primePoints[i] = component.BigQPrime
			doublePrimePoints[i] = component.BigQDoublePrime
		}
		p.state.theirBigQPrime[id] = primePoints
		p.state.theirBigQDoublePrime[id] = doublePrimePoints
	}

	var err error
	p.state.myPaillierSk, err = paillier.SampleSecretKey(uint(p.paillierKeyLen), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate Paillier secret key")
	}
	p.state.myPaillierPk = p.state.myPaillierSk.Public()

	rows := p.shareRows(p.SharingID())
	components := make([]*ComponentCiphertexts, len(rows))
	for i, row := range rows {
		cKeyPrime, rPrime, err := encryptScalar(p.state.myPaillierSk, p.state.myXPrime[i], p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot encrypt x' for MSP row %d", row)
		}
		cKeyDoublePrime, rDoublePrime, err := encryptScalar(p.state.myPaillierSk, p.state.myXDoublePrime[i], p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot encrypt x'' for MSP row %d", row)
		}
		p.state.myRPrime[i] = rPrime
		p.state.myRDoublePrime[i] = rDoublePrime
		components[i] = &ComponentCiphertexts{
			Row:             row,
			CKeyPrime:       cKeyPrime,
			CKeyDoublePrime: cKeyDoublePrime,
		}
	}

	for _, peer := range p.qualifiedPeers(p.SharingID()) {
		lpCtx, err := p.lpProofContext(p.SharingID(), peer, p.state.myPaillierPk)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create LP proof context for peer %d", peer)
		}
		p.state.lpProvers[peer], err = lp.NewProver(lpCtx, base.ComputationalSecurityBits, p.state.myPaillierSk, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create LP prover for peer %d", peer)
		}

		primeProvers := make([]*lpdl.Prover[P, B, S], len(rows))
		doublePrimeProvers := make([]*lpdl.Prover[P, B, S], len(rows))
		for i, row := range rows {
			primeCtx, err := p.lpdlProofContext(p.SharingID(), peer, pairProofLPDLPrime, row, p.state.myPaillierPk, p.state.myBigQPrime[i], components[i].CKeyPrime)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q' LPDL context for peer %d and MSP row %d", peer, row)
			}
			primeProvers[i], err = lpdl.NewProver(primeCtx, p.curve, p.state.myPaillierSk, p.state.myXPrime[i], p.state.myRPrime[i], p.prng)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q' LPDL prover for peer %d and MSP row %d", peer, row)
			}

			doublePrimeCtx, err := p.lpdlProofContext(p.SharingID(), peer, pairProofLPDLDoublePrime, row, p.state.myPaillierPk, p.state.myBigQDoublePrime[i], components[i].CKeyDoublePrime)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q'' LPDL context for peer %d and MSP row %d", peer, row)
			}
			doublePrimeProvers[i], err = lpdl.NewProver(doublePrimeCtx, p.curve, p.state.myPaillierSk, p.state.myXDoublePrime[i], p.state.myRDoublePrime[i], p.prng)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q'' LPDL prover for peer %d and MSP row %d", peer, row)
			}
		}
		p.state.lpdlPrimeProvers[peer] = primeProvers
		p.state.lpdlDoublePrimeProvers[peer] = doublePrimeProvers
	}

	p.round++
	return &Round3Broadcast[P, B, S]{
		Components:        components,
		PaillierPublicKey: p.state.myPaillierPk,
	}, nil
}

// Round4 records each qualified sender's encrypted raw-share component vector
// and starts the corresponding peer-bound LP and LPDL verifier roles.
func (p *Participant[P, B, S]) Round4(input network.RoundMessages[*Round3Broadcast[P, B, S], *Participant[P, B, S]]) (network.OutgoingUnicasts[*Round4P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 4 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 4, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-3 messages")
	}

	out := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id := range p.qualifiedPeersOrdered() {
		message, _ := input.Get(id)
		publicKey := message.PaillierPublicKey
		p.state.theirPaillierPublicKeys[id] = publicKey

		lpCtx, err := p.lpProofContext(id, p.SharingID(), publicKey)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create LP proof context for participant %d", id)
		}
		p.state.lpVerifiers[id], err = lp.NewVerifier(lpCtx, base.ComputationalSecurityBits, publicKey, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create LP verifier for participant %d", id)
		}

		outgoing := &Round4P2P[P, B, S]{
			LpRound1Output: nil,
			Components:     make([]*ComponentLPDLRound1Output[P, B, S], len(message.Components)),
		}
		outgoing.LpRound1Output, err = p.state.lpVerifiers[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of LP verifier for participant %d", id)
		}

		encryptedShares := make([]*paillier.Ciphertext, len(message.Components))
		primeVerifiers := make([]*lpdl.Verifier[P, B, S], len(message.Components))
		doublePrimeVerifiers := make([]*lpdl.Verifier[P, B, S], len(message.Components))
		for i, component := range message.Components {
			encryptedShares[i], err = publicKey.CiphertextOp(
				component.CKeyDoublePrime,
				component.CKeyPrime,
				component.CKeyPrime,
				component.CKeyPrime,
			)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot combine encrypted raw share component from participant %d at MSP row %d", id, component.Row)
			}

			primeCtx, err := p.lpdlProofContext(id, p.SharingID(), pairProofLPDLPrime, component.Row, publicKey, p.state.theirBigQPrime[id][i], component.CKeyPrime)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q' LPDL context for participant %d and MSP row %d", id, component.Row)
			}
			primeVerifiers[i], err = lpdl.NewVerifier(primeCtx, publicKey, p.state.theirBigQPrime[id][i], component.CKeyPrime, p.prng)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}

			doublePrimeCtx, err := p.lpdlProofContext(id, p.SharingID(), pairProofLPDLDoublePrime, component.Row, publicKey, p.state.theirBigQDoublePrime[id][i], component.CKeyDoublePrime)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q'' LPDL context for participant %d and MSP row %d", id, component.Row)
			}
			doublePrimeVerifiers[i], err = lpdl.NewVerifier(doublePrimeCtx, publicKey, p.state.theirBigQDoublePrime[id][i], component.CKeyDoublePrime, p.prng)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot create Q'' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}

			componentOutput := &ComponentLPDLRound1Output[P, B, S]{
				Row:                         component.Row,
				LpdlPrimeRound1Output:       nil,
				LpdlDoublePrimeRound1Output: nil,
			}
			componentOutput.LpdlPrimeRound1Output, err = primeVerifiers[i].Round1()
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 1 of Q' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}
			componentOutput.LpdlDoublePrimeRound1Output, err = doublePrimeVerifiers[i].Round1()
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 1 of Q'' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}
			outgoing.Components[i] = componentOutput
		}
		p.state.theirPaillierEncryptedShares[id] = encryptedShares
		p.state.lpdlPrimeVerifiers[id] = primeVerifiers
		p.state.lpdlDoublePrimeVerifiers[id] = doublePrimeVerifiers
		out.Put(id, outgoing)
	}

	p.round++
	return out.Freeze(), nil
}

// Round5 advances all pairwise LP and component-wise LPDL prover roles.
//
//nolint:dupl // false positive
func (p *Participant[P, B, S]) Round5(input network.RoundMessages[*Round4P2P[P, B, S], *Participant[P, B, S]]) (network.OutgoingUnicasts[*Round5P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 5 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 5, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.qualifiedPeersOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-4 messages")
	}

	out := hashmap.NewComparable[sharing.ID, *Round5P2P[P, B, S]]()
	for id := range p.qualifiedPeersOrdered() {
		message, _ := input.Get(id)
		outgoing := &Round5P2P[P, B, S]{
			LpRound2Output: nil,
			Components:     make([]*ComponentLPDLRound2Output[P, B, S], len(message.Components)),
		}
		var err error
		outgoing.LpRound2Output, err = p.state.lpProvers[id].Round2(message.LpRound1Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of LP prover for participant %d", id)
		}
		for i, component := range message.Components {
			componentOutput := &ComponentLPDLRound2Output[P, B, S]{
				Row:                         component.Row,
				LpdlPrimeRound2Output:       nil,
				LpdlDoublePrimeRound2Output: nil,
			}
			componentOutput.LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[id][i].Round2(component.LpdlPrimeRound1Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 2 of Q' LPDL prover for participant %d and MSP row %d", id, component.Row)
			}
			componentOutput.LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[id][i].Round2(component.LpdlDoublePrimeRound1Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 2 of Q'' LPDL prover for participant %d and MSP row %d", id, component.Row)
			}
			outgoing.Components[i] = componentOutput
		}
		out.Put(id, outgoing)
	}
	p.round++
	return out.Freeze(), nil
}

// Round6 advances all pairwise LP and component-wise LPDL verifier roles.
//
//nolint:dupl // false positive
func (p *Participant[P, B, S]) Round6(input network.RoundMessages[*Round5P2P[P, B, S], *Participant[P, B, S]]) (network.OutgoingUnicasts[*Round6P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 6 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 6, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.qualifiedPeersOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-5 messages")
	}

	out := hashmap.NewComparable[sharing.ID, *Round6P2P[P, B, S]]()
	for id := range p.qualifiedPeersOrdered() {
		message, _ := input.Get(id)
		outgoing := &Round6P2P[P, B, S]{
			LpRound3Output: nil,
			Components:     make([]*ComponentLPDLRound3Output[P, B, S], len(message.Components)),
		}
		var err error
		outgoing.LpRound3Output, err = p.state.lpVerifiers[id].Round3(message.LpRound2Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of LP verifier for participant %d", id)
		}
		for i, component := range message.Components {
			componentOutput := &ComponentLPDLRound3Output[P, B, S]{
				Row:                         component.Row,
				LpdlPrimeRound3Output:       nil,
				LpdlDoublePrimeRound3Output: nil,
			}
			componentOutput.LpdlPrimeRound3Output, err = p.state.lpdlPrimeVerifiers[id][i].Round3(component.LpdlPrimeRound2Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 3 of Q' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}
			componentOutput.LpdlDoublePrimeRound3Output, err = p.state.lpdlDoublePrimeVerifiers[id][i].Round3(component.LpdlDoublePrimeRound2Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 3 of Q'' LPDL verifier for participant %d and MSP row %d", id, component.Row)
			}
			outgoing.Components[i] = componentOutput
		}
		out.Put(id, outgoing)
	}
	p.round++
	return out.Freeze(), nil
}

// Round7 advances all pairwise LP and component-wise LPDL prover roles to their
// final responses.
//
//nolint:dupl // false positive
func (p *Participant[P, B, S]) Round7(input network.RoundMessages[*Round6P2P[P, B, S], *Participant[P, B, S]]) (network.OutgoingUnicasts[*Round7P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 7 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 7, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.qualifiedPeersOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-6 messages")
	}

	out := hashmap.NewComparable[sharing.ID, *Round7P2P[P, B, S]]()
	for id := range p.qualifiedPeersOrdered() {
		message, _ := input.Get(id)
		outgoing := &Round7P2P[P, B, S]{
			LpRound4Output: nil,
			Components:     make([]*ComponentLPDLRound4Output[P, B, S], len(message.Components)),
		}
		var err error
		outgoing.LpRound4Output, err = p.state.lpProvers[id].Round4(message.LpRound3Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 4 of LP prover for participant %d", id)
		}
		for i, component := range message.Components {
			componentOutput := &ComponentLPDLRound4Output[P, B, S]{
				Row:                         component.Row,
				LpdlPrimeRound4Output:       nil,
				LpdlDoublePrimeRound4Output: nil,
			}
			componentOutput.LpdlPrimeRound4Output, err = p.state.lpdlPrimeProvers[id][i].Round4(component.LpdlPrimeRound3Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 4 of Q' LPDL prover for participant %d and MSP row %d", id, component.Row)
			}
			componentOutput.LpdlDoublePrimeRound4Output, err = p.state.lpdlDoublePrimeProvers[id][i].Round4(component.LpdlDoublePrimeRound3Output)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot run round 4 of Q'' LPDL prover for participant %d and MSP row %d", id, component.Row)
			}
			outgoing.Components[i] = componentOutput
		}
		out.Put(id, outgoing)
	}
	p.round++
	return out.Freeze(), nil
}

// Round8 verifies every final LP and component-wise LPDL response and stores
// every qualified peer's encrypted raw MSP-share component vector.
func (p *Participant[P, B, S]) Round8(input network.RoundMessages[*Round7P2P[P, B, S], *Participant[P, B, S]]) (*lindell17.Shard[P, B, S], error) {
	if p.round != 8 {
		return nil, ErrRound.WithMessage(invalidRoundMessage, 8, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.qualifiedPeersOrdered(), input); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming round-7 messages")
	}
	for id := range p.qualifiedPeersOrdered() {
		message, _ := input.Get(id)
		if err := p.state.lpVerifiers[id].Round5(message.LpRound4Output); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify Paillier public key")
		}
		for i, component := range message.Components {
			if err := p.state.lpdlPrimeVerifiers[id][i].Round5(component.LpdlPrimeRound4Output); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify encrypted Q' discrete log for MSP row %d", component.Row)
			}
			if err := p.state.lpdlDoublePrimeVerifiers[id][i].Round5(component.LpdlDoublePrimeRound4Output); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify encrypted Q'' discrete log for MSP row %d", component.Row)
			}
		}
	}

	auxInfo, err := lindell17.NewAuxiliaryInfo(
		p.state.myPaillierSk,
		hashmap.NewComparableFromNativeLike(p.state.theirPaillierPublicKeys).Freeze(),
		hashmap.NewComparableFromNativeLike(p.state.theirPaillierEncryptedShares).Freeze(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create auxiliary info")
	}
	shard, err := lindell17.NewShard(p.baseShard, auxInfo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Lindell17 shard")
	}
	p.round++
	return shard, nil
}

func encryptScalar[S algebra.PrimeFieldElement[S]](secretKey *paillier.SecretKey, scalar S, prng io.Reader) (*paillier.Ciphertext, *paillier.Nonce, error) {
	x, err := num.N().FromBytes(scalar.Bytes())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert scalar to natural number")
	}
	plaintext, err := paillier.NewPlaintextFromNat(x, secretKey.Group().N())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert scalar to Paillier plaintext")
	}
	nonce, err := secretKey.SampleNonce(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample Paillier nonce")
	}
	ciphertext, err := secretKey.EncryptWithNonce(plaintext, nonce)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt scalar")
	}
	return ciphertext, nonce, nil
}

func (p *Participant[P, B, S]) pairContext(proverID, verifierID sharing.ID) (*session.Context, error) {
	ctx, err := p.ctx.SubContext(hashset.NewComparable(proverID, verifierID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create pairwise subcontext")
	}
	ctx.Transcript().AppendBytes(pairProverLabel, binary.BigEndian.AppendUint64(nil, uint64(proverID)))
	ctx.Transcript().AppendBytes(pairVerifierLabel, binary.BigEndian.AppendUint64(nil, uint64(verifierID)))
	return ctx, nil
}

func (p *Participant[P, B, S]) lpProofContext(proverID, verifierID sharing.ID, publicKey *paillier.PublicKey) (*session.Context, error) {
	ctx, err := p.pairContext(proverID, verifierID)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create LP pair context")
	}
	ctx.Transcript().AppendBytes(pairProofKindLabel, []byte(pairProofLP))
	ctx.Transcript().AppendBytes(pairPaillierKeyLabel, publicKey.Group().N().Bytes())
	return ctx, nil
}

func (p *Participant[P, B, S]) lpdlProofContext(
	proverID, verifierID sharing.ID,
	kind string,
	row int,
	publicKey *paillier.PublicKey,
	bigQ P,
	ciphertext *paillier.Ciphertext,
) (*session.Context, error) {
	ctx, err := p.pairContext(proverID, verifierID)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create LPDL pair context")
	}
	ctx.Transcript().AppendBytes(pairProofKindLabel, []byte(kind))
	ctx.Transcript().AppendBytes(pairPaillierKeyLabel, publicKey.Group().N().Bytes())
	ctx.Transcript().AppendBytes(pairRowLabel, binary.BigEndian.AppendUint64(nil, uint64(row)))
	ctx.Transcript().AppendBytes(pairPointLabel, bigQ.ToCompressed())
	ctx.Transcript().AppendBytes(pairCiphertextLabel, ciphertext.Bytes())
	return ctx, nil
}

func encodeComponentPoints[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](components []*ComponentDecomposition[P, B, S]) []byte {
	out := binary.BigEndian.AppendUint64(nil, uint64(len(components)))
	for _, component := range components {
		out = binary.BigEndian.AppendUint64(out, uint64(component.Row))
		primeBytes := component.BigQPrime.ToCompressed()
		doublePrimeBytes := component.BigQDoublePrime.ToCompressed()
		out = binary.BigEndian.AppendUint64(out, uint64(len(primeBytes)))
		out = append(out, primeBytes...)
		out = binary.BigEndian.AppendUint64(out, uint64(len(doublePrimeBytes)))
		out = append(out, doublePrimeBytes...)
	}
	return out
}

func triplePoint[P interface{ Add(P) P }](point P) P {
	return point.Add(point).Add(point)
}

func dlogProve[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](p *Participant[P, B, S], bigQ, bigQTwin P, x S, row int, half uint64) (compiler.NIZKPoKProof, error) {
	ctx := p.ctx.Clone()
	bindDlogTranscript(p, ctx, p.SharingID(), row, half, bigQ, bigQTwin)
	prover, err := p.state.niDlogScheme.NewProver(ctx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create discrete-log prover")
	}
	proof, err := prover.Prove(schnorrpok.NewStatement(bigQ), schnorrpok.NewWitness(x))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create discrete-log proof")
	}
	return proof, nil
}

func dlogVerify[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](p *Participant[P, B, S], proverID sharing.ID, proof compiler.NIZKPoKProof, bigQ, bigQTwin P, row int, half uint64) error {
	ctx := p.ctx.Clone()
	bindDlogTranscript(p, ctx, proverID, row, half, bigQ, bigQTwin)
	verifier, err := p.state.niDlogScheme.NewVerifier(ctx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create discrete-log verifier")
	}
	if err := verifier.Verify(schnorrpok.NewStatement(bigQ), proof); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify discrete-log proof for participant %d", proverID)
	}
	return nil
}

func bindDlogTranscript[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](p *Participant[P, B, S], ctx *session.Context, proverID sharing.ID, row int, half uint64, bigQ, bigQTwin P) {
	ctx.Transcript().AppendBytes(transcriptDLogSLabel, p.quorumBytes...)
	ctx.Transcript().AppendBytes(dlogProverLabel, binary.BigEndian.AppendUint64(nil, uint64(proverID)))
	ctx.Transcript().AppendBytes(dlogRowLabel, binary.BigEndian.AppendUint64(nil, uint64(row)))
	ctx.Transcript().AppendBytes(dlogHalfLabel, binary.BigEndian.AppendUint64(nil, half))
	ctx.Transcript().AppendBytes(dlogPointLabel, bigQ.ToCompressed())
	ctx.Transcript().AppendBytes(bigQTwinLabel, bigQTwin.ToCompressed())
}

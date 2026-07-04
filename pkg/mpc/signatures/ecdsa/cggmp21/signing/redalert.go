package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/affgstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/dec"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const (
	redAlertDecProofLabel      = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN_RED-ALERT-DEC"
	redAlertAffGStarProofLabel = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN_RED-ALERT-AFFGSTAR"
)

type redAlertBase[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] interface {
	signer() *Signer[P, B, S]
	decBase() P
	decWitness() (x, y *num.Int, xPoint, sPoint P, err error)
	decStatementPoints(party sharing.ID) (xPoint, sPoint P)
	affGStarWitness() (x S, xPoint P)
	affGStarStatementPoint(sender sharing.ID) P
	witnessMasks() (beta map[sharing.ID]*num.Int, s, r map[sharing.ID]*paillier.Nonce)
	sentCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext)
	receivedCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext)
}

type redAlertBaseNonce[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	s *Signer[P, B, S]
}

func newRedAlertNonce[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](s *Signer[P, B, S]) *RedAlertParticipant[P, B, S] {
	return &RedAlertParticipant[P, B, S]{
		base:           &redAlertBaseNonce[P, B, S]{s: s},
		localBroadcast: nil,
	}
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) signer() *Signer[P, B, S] {
	return n.s
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) decBase() P {
	return n.s.params.CurveGroup().Generator()
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) decWitness() (x, y *num.Int, xPoint, sPoint P, err error) {
	x, err = num.Z().FromUnsignedNumeric(n.s.state.gamma)
	if err != nil {
		return nil, nil, xPoint, sPoint, errs.Wrap(err).WithMessage("cannot convert gamma to integer")
	}
	return x, n.s.state.deltaInt, n.s.state.bigGammaJ[n.s.ctx.HolderID()], n.s.params.CurveGroup().ScalarBaseMul(n.s.state.delta), nil
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) decStatementPoints(party sharing.ID) (xPoint, sPoint P) {
	return n.s.state.bigGammaJ[party], n.s.params.CurveGroup().ScalarBaseMul(n.s.state.deltaJ[party])
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) affGStarWitness() (x S, xPoint P) {
	return n.s.state.gamma, n.s.state.bigGammaJ[n.s.ctx.HolderID()]
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) affGStarStatementPoint(sender sharing.ID) P {
	return n.s.state.bigGammaJ[sender]
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) witnessMasks() (beta map[sharing.ID]*num.Int, s, r map[sharing.ID]*paillier.Nonce) {
	return n.s.state.betaJ, n.s.state.sJ, n.s.state.rJ
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) sentCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext) {
	return n.s.state.bigDSentJ, n.s.state.bigFSentJ
}

//nolint:unused // false positive
func (n *redAlertBaseNonce[P, B, S]) receivedCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext) {
	return n.s.state.bigDReceivedJ, n.s.state.bigFReceivedJ
}

type redAlertBaseChi[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	s *Signer[P, B, S]
}

func newRedAlertChi[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](s *Signer[P, B, S]) *RedAlertParticipant[P, B, S] {
	return &RedAlertParticipant[P, B, S]{
		base:           &redAlertBaseChi[P, B, S]{s: s},
		localBroadcast: nil,
	}
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) signer() *Signer[P, B, S] {
	return c.s
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) decBase() P {
	return c.s.state.bigGamma
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) decWitness() (x, y *num.Int, xPoint, sPoint P, err error) {
	x, err = num.Z().FromUnsignedNumeric(c.s.state.x)
	if err != nil {
		return nil, nil, xPoint, sPoint, errs.Wrap(err).WithMessage("cannot convert x to integer")
	}
	return x, c.s.state.chiInt, c.s.state.partialPublicKeys[c.s.ctx.HolderID()], c.s.state.bigSJ[c.s.ctx.HolderID()], nil
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) decStatementPoints(party sharing.ID) (xPoint, sPoint P) {
	return c.s.state.partialPublicKeys[party], c.s.state.bigSJ[party]
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) affGStarWitness() (x S, xPoint P) {
	return c.s.state.x, c.s.state.partialPublicKeys[c.s.ctx.HolderID()]
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) affGStarStatementPoint(sender sharing.ID) P {
	return c.s.state.partialPublicKeys[sender]
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) witnessMasks() (beta map[sharing.ID]*num.Int, s, r map[sharing.ID]*paillier.Nonce) {
	return c.s.state.betaHatJ, c.s.state.sHatJ, c.s.state.rHatJ
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) sentCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext) {
	return c.s.state.bigDHatSentJ, c.s.state.bigFHatSentJ
}

//nolint:unused // false positive
func (c *redAlertBaseChi[P, B, S]) receivedCiphertexts() (d, f map[sharing.ID]*paillier.Ciphertext) {
	return c.s.state.bigDHatReceivedJ, c.s.state.bigFHatReceivedJ
}

// RedAlertParticipant runs the internal CGGMP21 signing red-alert path.
type RedAlertParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	base           redAlertBase[P, B, S]
	localBroadcast *RedAlertBroadcast[P, B, S]
}

// SharingID returns the red-alert participant party identifier.
func (p *RedAlertParticipant[P, B, S]) SharingID() sharing.ID {
	return p.signer().ctx.HolderID()
}

func (p *RedAlertParticipant[P, B, S]) signer() *Signer[P, B, S] {
	return p.base.signer()
}

// Round1 broadcasts the local red-alert openings and their NIZK proofs.
func (p *RedAlertParticipant[P, B, S]) Round1() (*RedAlertBroadcast[P, B, S], error) {
	if p.signer().state.round != 4 {
		return nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", p.signer().state.round, 4)
	}

	// step 1
	aggregateD, err := p.aggregateLocalD()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute local aggregate D")
	}

	// step 2
	phi, err := p.proveDec(aggregateD)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove red-alert dec statement")
	}

	// step 3
	phiJ := make(map[sharing.ID]compiler.NIZKPoKProof)
	for recipient := range p.signer().ctx.OtherPartiesOrdered() {
		proof, err := p.proveAffGStar(recipient)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot prove red-alert aff-g* statement for %d", recipient)
		}
		phiJ[recipient] = proof
	}

	sentD, sentF := p.base.sentCiphertexts()
	out := &RedAlertBroadcast[P, B, S]{
		BigD: cloneCiphertextMap(sentD),
		BigF: cloneCiphertextMap(sentF),
		Phi:  phi,
		PhiJ: phiJ,
	}
	p.localBroadcast = out
	return out, nil
}

// Round2 verifies all red-alert broadcasts and returns an identifiable abort on the first bad proof.
func (p *RedAlertParticipant[P, B, S]) Round2(r1b network.RoundMessages[*RedAlertBroadcast[P, B, S], *RedAlertParticipant[P, B, S]]) error {
	if err := network.ValidateIncomingMessages(p, p.signer().ctx.OtherPartiesOrdered(), r1b); err != nil {
		return errs.Wrap(err).WithMessage("invalid red alert broadcasts")
	}

	messages := map[sharing.ID]*RedAlertBroadcast[P, B, S]{
		p.signer().ctx.HolderID(): p.localBroadcast,
	}
	for id := range p.signer().ctx.OtherPartiesOrdered() {
		msg, _ := r1b.Get(id)
		messages[id] = msg
	}

	for id := range p.signer().ctx.AllPartiesOrdered() {
		aggregateD, err := p.aggregateBroadcastD(id, messages)
		if err != nil {
			return errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot compute aggregate D for %d", id)
		}

		// step 1
		if err := p.verifyDec(id, aggregateD, messages[id].Phi); err != nil {
			return errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify red-alert dec proof for %d", id)
		}
	}

	for sender := range p.signer().ctx.AllPartiesOrdered() {
		for recipient := range p.signer().ctx.AllPartiesOrdered() {
			if recipient == sender {
				continue
			}
			msg := messages[sender]

			// step 2
			if err := p.verifyAffGStar(sender, recipient, msg.BigD[recipient], msg.BigF[recipient], msg.PhiJ[recipient]); err != nil {
				return errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage(
					"cannot verify red-alert aff-g* proof from %d to %d",
					sender,
					recipient,
				)
			}
		}
	}

	for id := range p.signer().ctx.AllPartiesOrdered() {
		data, err := serde.MarshalCBOR(messages[id])
		if err != nil {
			return errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot serialise red alert broadcast from %d", id)
		}
		p.signer().ctx.Transcript().AppendBytes(redAlertBroadcastTranscriptLabel, id.Bytes(), data)
	}
	return nil
}

func (p *RedAlertParticipant[P, B, S]) aggregateLocalD() (*paillier.Ciphertext, error) {
	receivedD, _ := p.base.receivedCiphertexts()
	_, sentF := p.base.sentCiphertexts()
	localPaillierPublicKey := p.signer().shard.AuxInfo().PaillierSecretKey().Public()

	var out *paillier.Ciphertext
	for id := range p.signer().ctx.OtherPartiesOrdered() {
		pair, err := localPaillierPublicKey.CiphertextOp(receivedD[id], sentF[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot combine local D/F for %d", id)
		}
		if out == nil {
			out = pair
			continue
		}
		out, err = localPaillierPublicKey.CiphertextOp(out, pair)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot aggregate local D/F for %d", id)
		}
	}
	if out == nil {
		return nil, cggmp21.ErrFailed.WithMessage("empty red-alert aggregate")
	}
	return out, nil
}

func (p *RedAlertParticipant[P, B, S]) aggregateBroadcastD(
	recipient sharing.ID,
	messages map[sharing.ID]*RedAlertBroadcast[P, B, S],
) (*paillier.Ciphertext, error) {
	recipientPaillierPublicKey, err := paillierPublicKeyFor(p.signer(), recipient)
	if err != nil {
		return nil, err
	}
	recipientMessage := messages[recipient]
	var out *paillier.Ciphertext
	for sender := range p.signer().ctx.AllPartiesOrdered() {
		if sender == recipient {
			continue
		}
		pair, err := recipientPaillierPublicKey.CiphertextOp(messages[sender].BigD[recipient], recipientMessage.BigF[sender])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot combine broadcast D/F for sender %d", sender)
		}
		if out == nil {
			out = pair
			continue
		}
		out, err = recipientPaillierPublicKey.CiphertextOp(out, pair)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot aggregate broadcast D/F for sender %d", sender)
		}
	}
	if out == nil {
		return nil, cggmp21.ErrFailed.WithMessage("empty red-alert aggregate")
	}
	return out, nil
}

func (p *RedAlertParticipant[P, B, S]) proveDec(aggregateD *paillier.Ciphertext) (compiler.NIZKPoKProof, error) {
	x, y, xPoint, sPoint, err := p.base.decWitness()
	if err != nil {
		return nil, err
	}
	sk := p.signer().shard.AuxInfo().PaillierSecretKey()
	kX, err := sk.CiphertextScalarOp(p.signer().state.bigKJ[p.signer().ctx.HolderID()], x)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute K^x")
	}
	opened, err := sk.CiphertextOp(kX, aggregateD)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute opened dec ciphertext")
	}
	_, rho, err := sk.Open(opened)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot open dec ciphertext randomizer")
	}

	decSigma, err := dec.NewProtocol(p.signer().params.L(), p.signer().params.LPrime(), p.signer().params.Epsilon(), p.base.decBase(), p.signer().prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dec protocol")
	}
	statement, err := dec.NewStatement(sk.Public(), p.signer().state.bigKJ[p.signer().ctx.HolderID()], xPoint, aggregateD, sPoint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dec statement")
	}
	witness, err := dec.NewWitness(x, y, rho)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dec witness")
	}
	decNI, err := fiatshamir.NewCompiler(decSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI dec compiler")
	}
	proverCtx := p.signer().ctx.Clone()
	proverCtx.Transcript().AppendBytes(redAlertDecProofLabel, p.signer().ctx.HolderID().Bytes())
	prover, err := decNI.NewProver(proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dec prover")
	}
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create red-alert dec proof")
	}
	return proof, nil
}

func (p *RedAlertParticipant[P, B, S]) proveAffGStar(recipient sharing.ID) (compiler.NIZKPoKProof, error) {
	recipientPaillierPublicKey, err := paillierPublicKeyFor(p.signer(), recipient)
	if err != nil {
		return nil, err
	}
	localPaillierPublicKey := p.signer().shard.AuxInfo().PaillierSecretKey().Public()
	xScalar, xPoint := p.base.affGStarWitness()
	x, err := num.Z().FromUnsignedNumeric(xScalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert witness scalar to integer")
	}
	betaJ, sJ, rJ := p.base.witnessMasks()
	y := betaJ[recipient].Neg()
	yPlaintext, err := paillier.NewPlaintextSymmetric(y, localPaillierPublicKey.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create aff-g* plaintext")
	}
	rInv, err := localPaillierPublicKey.NonceOpInv(rJ[recipient])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert F nonce")
	}
	sentD, sentF := p.base.sentCiphertexts()
	bigFInv, err := localPaillierPublicKey.CiphertextOpInv(sentF[recipient])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert F ciphertext")
	}

	affgSigma, err := affgstar.NewProtocol(p.signer().params.L(), p.signer().params.LPrime(), p.signer().params.Epsilon(), p.signer().params.CurveGroup(), p.signer().prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create aff-g* protocol")
	}
	statement, err := affgstar.NewStatement(recipientPaillierPublicKey, localPaillierPublicKey, p.signer().state.bigKJ[recipient], sentD[recipient], bigFInv, xPoint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create aff-g* statement")
	}
	witness, err := affgstar.NewWitness(x, yPlaintext, sJ[recipient], rInv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create aff-g* witness")
	}
	affgNI, err := fiatshamir.NewCompiler(affgSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI aff-g* compiler")
	}
	proverCtx := p.signer().ctx.Clone()
	proverCtx.Transcript().AppendBytes(redAlertAffGStarProofLabel, p.signer().ctx.HolderID().Bytes(), recipient.Bytes())
	prover, err := affgNI.NewProver(proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create aff-g* prover")
	}
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create red-alert aff-g* proof")
	}
	return proof, nil
}

func (p *RedAlertParticipant[P, B, S]) verifyDec(party sharing.ID, aggregateD *paillier.Ciphertext, proof compiler.NIZKPoKProof) error {
	paillierPublicKey, err := paillierPublicKeyFor(p.signer(), party)
	if err != nil {
		return err
	}
	xPoint, sPoint := p.base.decStatementPoints(party)
	decSigma, err := dec.NewProtocol(p.signer().params.L(), p.signer().params.LPrime(), p.signer().params.Epsilon(), p.base.decBase(), p.signer().prng)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dec protocol")
	}
	statement, err := dec.NewStatement(paillierPublicKey, p.signer().state.bigKJ[party], xPoint, aggregateD, sPoint)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dec statement")
	}
	decNI, err := fiatshamir.NewCompiler(decSigma)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create NI dec compiler")
	}
	verifierCtx := p.signer().ctx.Clone()
	verifierCtx.Transcript().AppendBytes(redAlertDecProofLabel, party.Bytes())
	verifier, err := decNI.NewVerifier(verifierCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dec verifier")
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("red-alert dec proof failed")
	}
	return nil
}

func (p *RedAlertParticipant[P, B, S]) verifyAffGStar(
	sender sharing.ID,
	recipient sharing.ID,
	bigD *paillier.Ciphertext,
	bigF *paillier.Ciphertext,
	proof compiler.NIZKPoKProof,
) error {
	recipientPaillierPublicKey, err := paillierPublicKeyFor(p.signer(), recipient)
	if err != nil {
		return err
	}
	senderPaillierPublicKey, err := paillierPublicKeyFor(p.signer(), sender)
	if err != nil {
		return err
	}
	xPoint := p.base.affGStarStatementPoint(sender)
	bigFInv, err := senderPaillierPublicKey.CiphertextOpInv(bigF)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot invert F ciphertext")
	}
	affgSigma, err := affgstar.NewProtocol(p.signer().params.L(), p.signer().params.LPrime(), p.signer().params.Epsilon(), p.signer().params.CurveGroup(), p.signer().prng)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create aff-g* protocol")
	}
	statement, err := affgstar.NewStatement(recipientPaillierPublicKey, senderPaillierPublicKey, p.signer().state.bigKJ[recipient], bigD, bigFInv, xPoint)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create aff-g* statement")
	}
	affgNI, err := fiatshamir.NewCompiler(affgSigma)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create NI aff-g* compiler")
	}
	verifierCtx := p.signer().ctx.Clone()
	verifierCtx.Transcript().AppendBytes(redAlertAffGStarProofLabel, sender.Bytes(), recipient.Bytes())
	verifier, err := affgNI.NewVerifier(verifierCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create aff-g* verifier")
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("red-alert aff-g* proof failed")
	}
	return nil
}

func cloneCiphertextMap(in map[sharing.ID]*paillier.Ciphertext) map[sharing.ID]*paillier.Ciphertext {
	out := make(map[sharing.ID]*paillier.Ciphertext, len(in))
	for id, ciphertext := range in {
		out[id] = ciphertext
	}
	return out
}

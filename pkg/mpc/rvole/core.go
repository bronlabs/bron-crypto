package rvole

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

type participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	copartyID sharing.ID
	suite     *Suite[P, B, S]
	prng      io.Reader
	g         []S
}

// Alice is the party with input a ∈ Z_q^ℓ. She is the OT sender: she holds
// both outputs of every OT, of message type M.
type Alice[M ot.Message, P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	multiplied bool
}

// Bob is the party that receives a random b. He is the OT receiver: he holds
// the choice bits β and one output per OT, of message type M.
type Bob[M ot.Message, P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	beta     ot.Choices
	gamma    [][]S
	chosen   bool
	finished bool
}

// newParticipant validates the shared inputs, appends the protocol's domain
// separator and derives the gadget vector g ∈ Z_q^ξ from the session
// identifier. Both roles must construct their participant at the same point
// of the session so that their transcripts stay aligned for θ and μ.
func newParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader) (participant[P, B, S], error) {
	if ctx == nil || suite == nil || prng == nil {
		return participant[P, B, S]{}, ErrInvalidArgument.WithMessage("context, suite and prng must not be nil")
	}
	if size := ctx.Quorum().Size(); size != 2 {
		return participant[P, B, S]{}, ErrInvalidArgument.WithMessage("quorum has %d parties, expected 2", size)
	}
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%d-%d", transcriptLabel, suite.l, suite.xi))

	g, err := deriveGadget(ctx, suite)
	if err != nil {
		return participant[P, B, S]{}, errs.Wrap(err).WithMessage("cannot derive the gadget vector")
	}
	return participant[P, B, S]{
		ctx:       ctx,
		copartyID: slices.Collect(ctx.OtherPartiesOrdered())[0],
		suite:     suite,
		prng:      prng,
		g:         g,
	}, nil
}

// deriveGadget derives the gadget vector g ∈ Z_q^ξ from the session
// identifier and the parameters ℓ, ξ alone, as the common reference string of
// the session (DKLs23 Protocol 5.2, footnote a; Asharov, Theorem B.17, where
// g = RO(sid)). It is fixed before any message is exchanged, so neither party
// can influence it, which the Variant III bound on ξ relies on: a g that
// depended on the OT messages could be ground by Alice into one that weakens
// the extraction of b, the adversary of Asharov's Variant II. The derivation
// uses a standalone transcript so that it is independent of whatever else ran
// on the session.
func deriveGadget[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S]) ([]S, error) {
	sid := ctx.SessionID()
	transcript := hagrid.NewTranscript(gadgetTranscriptLabel)
	transcript.AppendBytes(gadgetSeedLabel, sid[:], binary.LittleEndian.AppendUint64(nil, uint64(suite.l)), binary.LittleEndian.AppendUint64(nil, uint64(suite.xi)))

	g := make([]S, suite.xi)
	for j := range g {
		raw, err := transcript.ExtractBytes(gadgetLabel, uint(suite.field.WideElementSize()))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot extract gadget element %d", j)
		}
		g[j], err = suite.field.FromWideBytes(raw)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot reduce gadget element %d", j)
		}
	}
	return g, nil
}

// CopartyID returns the identifier of the other party.
func (p *participant[P, B, S]) CopartyID() sharing.ID {
	return p.copartyID
}

// Suite returns the protocol parameters.
func (p *participant[P, B, S]) Suite() *Suite[P, B, S] {
	return p.suite
}

// NewAlice builds Alice's core on the two-party session ctx, drawing the
// masking column from prng, which must be cryptographically secure.
func NewAlice[M ot.Message, P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader) (*Alice[M, P, B, S], error) {
	p, err := newParticipant(ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Alice")
	}
	return &Alice[M, P, B, S]{participant: p, multiplied: false}, nil
}

// NewBob builds Bob's core on the two-party session ctx.
func NewBob[M ot.Message, P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader) (*Bob[M, P, B, S], error) {
	p, err := newParticipant(ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Bob")
	}
	return &Bob[M, P, B, S]{participant: p, beta: nil, gamma: nil, chosen: false, finished: false}, nil
}

// ValidateInput checks that a is a well-formed input: exactly ℓ non-nil
// elements of the suite's field. The instantiations call it before their OT
// step, so that a bad input never advances the OT state or the transcript.
func (alice *Alice[M, P, B, S]) ValidateInput(a []S) error {
	if len(a) != alice.suite.l {
		return ErrInvalidArgument.WithMessage("input holds %d elements, expected %d", len(a), alice.suite.l)
	}
	for i, ai := range a {
		if utils.IsNil(ai) {
			return ErrInvalidArgument.WithMessage("input element %d must not be nil", i)
		}
		if ai.Structure().Name() != alice.suite.field.Name() {
			return ErrInvalidArgument.WithMessage("input element %d is of %s, expected %s", i, ai.Structure().Name(), alice.suite.field.Name())
		}
	}
	return nil
}

// Multiply is Alice's step once the ξ OTs have run: it expands both outputs of
// every OT into α_j⁰, α_j¹ ∈ Z_q^{ℓ+ρ}, masks the input a (and ρ random masks
// â) into ã_j = α_j⁰ − α_j¹ + (a ‖ â), derives θ from the transcript, which at
// this point must already bind the OT messages, and answers the consistency
// check with η and μ. It returns the message for Bob and Alice's output c with
// c_i = −Σ_j g_j·α_{j,i}⁰. It runs once per participant.
func (alice *Alice[M, P, B, S]) Multiply(pairs [][2]M, a []S) (*MultiplyMessage[P, B, S], []S, error) {
	if alice.multiplied {
		return nil, nil, ErrRound.WithMessage("Alice has already multiplied")
	}
	l, xi, field := alice.suite.l, alice.suite.xi, alice.suite.field
	if len(pairs) != xi {
		return nil, nil, ErrInvalidArgument.WithMessage("%d OT outputs, expected %d", len(pairs), xi)
	}
	if err := alice.ValidateInput(a); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid input")
	}

	alpha := make([][2][]S, xi)
	for j, pair := range pairs {
		for c := range 2 {
			var err error
			alpha[j][c], err = expand(field, pair[c], l+rho)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot expand row %d, branch %d", j, c)
			}
		}
	}

	c := make([]S, l)
	for i := range l {
		c[i] = field.Zero()
		for j := range xi {
			c[i] = c[i].Sub(alice.g[j].Mul(alpha[j][0][i]))
		}
	}

	aHat := make([]S, rho)
	for k := range rho {
		var err error
		aHat[k], err = field.Random(alice.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample the masking column")
		}
	}
	aFull := append(append(make([]S, 0, l+rho), a...), aHat...)

	aTilde := make([][]S, xi)
	for j := range xi {
		aTilde[j] = make([]S, l+rho)
		for i := range l + rho {
			aTilde[j][i] = alpha[j][0][i].Sub(alpha[j][1][i]).Add(aFull[i])
		}
	}

	theta, err := alice.deriveTheta(aTilde)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("consistency check")
	}

	eta := make([]S, rho)
	for k := range rho {
		eta[k] = aHat[k]
		for i := range l {
			eta[k] = eta[k].Add(theta[i][k].Mul(a[i]))
		}
	}

	muVector := make([][]S, xi)
	for j := range xi {
		muVector[j] = make([]S, rho)
		for k := range rho {
			muVector[j][k] = alpha[j][0][l+k]
			for i := range l {
				muVector[j][k] = muVector[j][k].Add(theta[i][k].Mul(alpha[j][0][i]))
			}
		}
	}
	mu, err := alice.deriveMu(muVector)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("consistency check")
	}

	alice.multiplied = true
	return &MultiplyMessage[P, B, S]{ATilde: aTilde, Eta: eta, Mu: mu}, c, nil
}

// Choose is Bob's step once the ξ OTs have run: it takes his choice bits β and
// the ξ received outputs, expands them into the rows γ_j ∈ Z_q^{ℓ+ρ} and
// returns b = ⟨g, β⟩. It runs once per participant.
func (bob *Bob[M, P, B, S]) Choose(choices ot.Choices, keys []M) (S, error) {
	var nilS S
	if bob.chosen {
		return nilS, ErrRound.WithMessage("Bob has already chosen")
	}
	xi, field := bob.suite.xi, bob.suite.field
	if len(keys) != xi {
		return nilS, ErrInvalidArgument.WithMessage("%d OT outputs, expected %d", len(keys), xi)
	}
	if choices.BitLen() != xi {
		return nilS, ErrInvalidArgument.WithMessage("%d choice bits, expected %d", choices.BitLen(), xi)
	}

	gamma := make([][]S, xi)
	for j, key := range keys {
		var err error
		gamma[j], err = expand(field, key, bob.suite.l+rho)
		if err != nil {
			return nilS, errs.Wrap(err).WithMessage("cannot expand row %d", j)
		}
	}
	bob.beta = choices
	bob.gamma = gamma

	b := field.Zero()
	for j := range xi {
		b = b.Add(bob.g[j].Mul(bob.bitElement(j)))
	}
	bob.chosen = true
	return b, nil
}

// Finish is Bob's last step: it validates Alice's message, unmasks his rows,
// d̃_j = γ_j + β_j·ã_j, verifies the consistency check and returns Bob's output
// d with d_i = Σ_j g_j·d̃_{j,i}. A failed check is an identifiable abort
// attributed to Alice. It runs once, after Choose.
func (bob *Bob[M, P, B, S]) Finish(m *MultiplyMessage[P, B, S]) ([]S, error) {
	if !bob.chosen || bob.finished {
		return nil, ErrRound.WithMessage("Finish needs Choose first and runs once")
	}
	if err := bob.ValidateMultiply(m, bob.copartyID); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid message")
	}
	l, xi, field := bob.suite.l, bob.suite.xi, bob.suite.field

	theta, err := bob.deriveTheta(m.ATilde)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("consistency check")
	}

	dTilde := make([][]S, xi)
	muVector := make([][]S, xi)
	for j := range xi {
		betaJ := bob.bitElement(j)
		dTilde[j] = make([]S, l+rho)
		for i := range l + rho {
			dTilde[j][i] = bob.gamma[j][i].Add(betaJ.Mul(m.ATilde[j][i]))
		}
		muVector[j] = make([]S, rho)
		for k := range rho {
			muVector[j][k] = dTilde[j][l+k].Sub(betaJ.Mul(m.Eta[k]))
			for i := range l {
				muVector[j][k] = muVector[j][k].Add(theta[i][k].Mul(dTilde[j][i]))
			}
		}
	}
	mu, err := bob.deriveMu(muVector)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("consistency check")
	}
	bob.finished = true
	if _, equal, _ := ct.CompareBytes(m.Mu, mu); equal != ct.True {
		return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, bob.copartyID).WithMessage("consistency check failed")
	}

	d := make([]S, l)
	for i := range l {
		d[i] = field.Zero()
		for j := range xi {
			d[i] = d[i].Add(bob.g[j].Mul(dTilde[j][i]))
		}
	}
	return d, nil
}

// bitElement returns β_j as a field element.
func (bob *Bob[M, P, B, S]) bitElement(j int) S {
	if (bob.beta[j/8]>>(j%8))&0b1 == 1 {
		return bob.suite.field.One()
	}
	return bob.suite.field.Zero()
}

// deriveTheta binds ã to the transcript and extracts the challenge
// θ ∈ Z_q^{ℓ×ρ}. The transcript already holds the OT messages, so θ depends on
// the whole OT transcript (Asharov, Section 4.5).
func (p *participant[P, B, S]) deriveTheta(aTilde [][]S) ([][]S, error) {
	for _, row := range aTilde {
		for _, e := range row {
			p.ctx.Transcript().AppendBytes(aTildeLabel, e.Bytes())
		}
	}
	theta := make([][]S, p.suite.l)
	for i := range theta {
		theta[i] = make([]S, rho)
		for k := range rho {
			raw, err := p.ctx.Transcript().ExtractBytes(thetaLabel, uint(p.suite.field.WideElementSize()))
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot extract theta")
			}
			theta[i][k], err = p.suite.field.FromWideBytes(raw)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot reduce theta")
			}
		}
	}
	return theta, nil
}

// deriveMu binds the check vector to the transcript and extracts its digest.
func (p *participant[P, B, S]) deriveMu(muVector [][]S) ([]byte, error) {
	for _, row := range muVector {
		for _, e := range row {
			p.ctx.Transcript().AppendBytes(muVectorLabel, e.Bytes())
		}
	}
	mu, err := p.ctx.Transcript().ExtractBytes(muLabel, base.CollisionResistanceBytesCeil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract mu")
	}
	return mu, nil
}

package signing

import (
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	pairLabel = "BRON_CRYPTO-DKLS23-SIGNING-PAIR-"
	ckLabel   = "BRON_CRYPTO-DKLS23-SIGNING-CK-"
	// mulLength is ℓ of the rVOLE: Alice's inputs are r_i and sk_i.
	mulLength = 2
)

// Opening is a party's opening of its commitment to R_i together with its
// additive public-key share pk_i, broadcast in the round of Alice's rVOLE
// message (the paper's round 2).
type Opening[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P
	BigRWitness hashcom.Witness
	Pk          P
}

// ValidateOpening checks that an opening is complete and that its points are
// non-identity elements of the prime-order group. Signing rejects degenerate
// point contributions at the message boundary. In the honest uniform model,
// each opening point is the identity with probability 1/q, where q is the
// scalar field order. This is about 2^-256 on secp256k1 and P-256.
func ValidateOpening[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](opening *Opening[P, B, S]) error {
	if opening == nil || utils.IsNil(opening.BigR) || utils.IsNil(opening.Pk) {
		return ErrValidation.WithMessage("opening and its points must not be nil")
	}
	if opening.BigRWitness == [hashcom.DigestSize]byte{} {
		return ErrValidation.WithMessage("witness must not be empty")
	}
	if opening.BigR.IsZero() || !opening.BigR.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid R")
	}
	if opening.Pk.IsZero() || !opening.Pk.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid pk")
	}
	return nil
}

// CheckValues are the values Alice of one rVOLE sends to Bob with her
// multiplication message: Γ^u = c^u·G, Γ^v = c^v·G and ψ = φ_i − χ_{i,j}.
type CheckValues[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	GammaU P
	GammaV P
	Psi    S
}

// ValidateCheckValues checks that the values are present and that the check
// points satisfy the same non-identity rule as opening points. In the ideal
// rVOLE model, each check point is the identity with probability 1/q.
func ValidateCheckValues[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](check *CheckValues[P, B, S]) error {
	if check == nil || utils.IsNil(check.GammaU) || utils.IsNil(check.GammaV) || utils.IsNil(check.Psi) {
		return ErrValidation.WithMessage("check values must not be nil")
	}
	if check.GammaU.IsZero() || !check.GammaU.IsTorsionFree() || check.GammaV.IsZero() || !check.GammaV.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid check points")
	}
	return nil
}

// ValidateCommitment checks that a commitment to R_i is present.
func ValidateCommitment(commitment hashcom.Commitment) error {
	if commitment == [hashcom.DigestSize]byte{} {
		return ErrValidation.WithMessage("commitment must not be empty")
	}
	return nil
}

// Core is the part of a cosigner that does not depend on how the random VOLE
// is instantiated: the session and key material, the commitment to R_i, the
// additive key share, the check values, the final checks, the partial
// signature and the state the cosigning aggregator needs afterwards. An
// instantiation calls its steps in the order of Protocol 3.6: Commit, then
// ReceiveCommitment and ReceiveChi for every counterparty, AliceInput,
// CheckValues for every counterparty and Opening, then ReceiveOpening and
// Verify for every counterparty and Finish.
type Core[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx           *session.Context
	shard         *dkls23.Shard[P, B, S]
	suite         *ecdsa.Suite[P, B, S]
	sharingScheme *feldman.Scheme[P, S]
	prng          io.Reader
	mulSuite      *rvole.Suite[P, B, S]

	ck             *hashcom.CommitmentKey
	r              S
	phi            S
	sk             S
	bigR           map[sharing.ID]P
	bigRCommitment map[sharing.ID]hashcom.Commitment
	bigRWitness    hashcom.Witness
	chi            map[sharing.ID]S
	c              map[sharing.ID][]S
	pk             map[sharing.ID]P
	verified       map[sharing.ID]bool
	psi            S
	cuDu           S
	cvDv           S
	committed      bool
	keyed          bool
	signed         bool
	aggregated     bool

	// Kept after Finish for the cosigning aggregator: the aggregated nonce
	// point R, its x-coordinate r_x as a scalar and the message scalar H(m).
	nonce   P
	rx      S
	m       S
	message []byte
}

// NewCore validates the session against the shard, builds the sharing schemes
// and the rVOLE suite, and appends the instantiation's domain separator with
// the session identifier to the main transcript. The quorum of ctx must be
// qualified for the shard's access structure.
func NewCore[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], shard *dkls23.Shard[P, B, S], prng io.Reader, transcriptLabel string) (*Core[P, B, S], error) {
	if ctx == nil || suite == nil || shard == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("context, suite, shard and prng must not be nil")
	}
	if transcriptLabel == "" {
		return nil, ErrInvalidArgument.WithMessage("transcript label must not be empty")
	}
	if suite.IsDeterministic() {
		return nil, ErrInvalidArgument.WithMessage("suite must be non-deterministic")
	}
	if ctx.HolderID() != shard.Share().ID() {
		return nil, ErrInvalidArgument.WithMessage("session holder %d does not hold share %d", ctx.HolderID(), shard.Share().ID())
	}
	if !ctx.Quorum().Contains(shard.Share().ID()) {
		return nil, ErrInvalidArgument.WithMessage("share %d is not part of the quorum", shard.Share().ID())
	}
	if !shard.MSP().Accepts(ctx.Quorum().List()...) {
		return nil, ErrInvalidArgument.WithMessage("unqualified quorum")
	}

	kwScheme, err := kw.NewInducedScheme(shard.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the sharing scheme")
	}
	curve := algebra.StructureMustBeAs[ecdsa.Curve[P, B, S]](shard.PublicKeyValue().Structure())
	vssScheme, err := feldman.NewSchemeFromKW(curve, kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the Feldman scheme")
	}
	mulSuite, err := rvole.NewSuite(mulLength, suite.Curve())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the rVOLE suite")
	}
	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%x", transcriptLabel, sid[:]))

	field := suite.ScalarField()
	//nolint:exhaustruct // filled in as the steps progress
	return &Core[P, B, S]{
		ctx:            ctx,
		shard:          shard,
		suite:          suite,
		sharingScheme:  vssScheme,
		prng:           prng,
		mulSuite:       mulSuite,
		bigR:           make(map[sharing.ID]P),
		bigRCommitment: make(map[sharing.ID]hashcom.Commitment),
		chi:            make(map[sharing.ID]S),
		c:              make(map[sharing.ID][]S),
		pk:             make(map[sharing.ID]P),
		verified:       make(map[sharing.ID]bool),
		psi:            field.Zero(),
		cuDu:           field.Zero(),
		cvDv:           field.Zero(),
	}, nil
}

// Ctx returns the signing session.
func (c *Core[P, B, S]) Ctx() *session.Context {
	return c.ctx
}

// SharingID returns the party's sharing identifier.
func (c *Core[P, B, S]) SharingID() sharing.ID {
	return c.ctx.HolderID()
}

// Quorum returns the signing quorum.
func (c *Core[P, B, S]) Quorum() network.Quorum {
	return c.ctx.Quorum()
}

// Suite returns the ECDSA suite.
func (c *Core[P, B, S]) Suite() *ecdsa.Suite[P, B, S] {
	return c.suite
}

// MulSuite returns the rVOLE suite, ℓ = 2 over the suite's curve.
func (c *Core[P, B, S]) MulSuite() *rvole.Suite[P, B, S] {
	return c.mulSuite
}

// Prng returns the randomness source.
func (c *Core[P, B, S]) Prng() io.Reader {
	return c.prng
}

// PairContext derives the pairwise sub-session of the ordered pair (Alice,
// Bob); both parties derive the same one, and the OTs and the rVOLE of that
// pair all run on it, so the rVOLE challenge binds everything the pair
// exchanged.
func (c *Core[P, B, S]) PairContext(aliceID, bobID sharing.ID) (*session.Context, error) {
	pair, err := c.ctx.SubContext(hashset.NewComparable(aliceID, bobID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the sub-session")
	}
	pair.Transcript().AppendBytes(pairLabel, binary.LittleEndian.AppendUint64(nil, uint64(aliceID)), binary.LittleEndian.AppendUint64(nil, uint64(bobID)))
	return pair, nil
}

// Commit extracts the commitment key from the transcript, samples the instance
// key r_i and the inversion mask φ_i, and commits to R_i = r_i·G; it returns
// the commitment to broadcast.
func (c *Core[P, B, S]) Commit() (hashcom.Commitment, error) {
	if c.committed {
		return hashcom.Commitment{}, ErrRound.WithMessage("already committed")
	}
	me := c.ctx.HolderID()
	var err error
	c.ck, err = hashcom.ExtractCommitmentKey(c.ctx.Transcript(), ckLabel)
	if err != nil {
		return hashcom.Commitment{}, errs.Wrap(err).WithMessage("cannot derive the commitment key")
	}
	c.r, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return hashcom.Commitment{}, errs.Wrap(err).WithMessage("cannot sample r")
	}
	c.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return hashcom.Commitment{}, errs.Wrap(err).WithMessage("cannot sample phi")
	}
	c.bigR[me] = c.suite.Curve().ScalarBaseMul(c.r)
	c.bigRCommitment[me], c.bigRWitness, err = commitments.Commit(c.ck, c.bigR[me].ToCompressed(), c.prng)
	if err != nil {
		return hashcom.Commitment{}, errs.Wrap(err).WithMessage("cannot commit to R")
	}
	c.committed = true
	return c.bigRCommitment[me], nil
}

// ReceiveCommitment stores a counterparty's commitment to R_j.
func (c *Core[P, B, S]) ReceiveCommitment(id sharing.ID, commitment hashcom.Commitment) {
	c.bigRCommitment[id] = commitment
}

// ReceiveChi stores χ_{i,j}, Bob's random output b of the rVOLE with id.
func (c *Core[P, B, S]) ReceiveChi(id sharing.ID, chi S) {
	c.chi[id] = chi
}

// keyShare derives, once, the additive key share sk_i = share + ζ_i with the
// zero share ζ_i of the session's pairwise seeds, and pk_i = sk_i·G.
func (c *Core[P, B, S]) keyShare() error {
	if c.keyed {
		return nil
	}
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](c.shard.Share().Value()[0].Structure())
	zeta, err := przs.SampleZeroShare(c.ctx, field)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot sample the zero share")
	}
	quorum, err := unanimity.NewUnanimityAccessStructure(c.ctx.Quorum())
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create the unanimity access structure")
	}
	sk, err := c.sharingScheme.ConvertShareToAdditive(c.shard.Share(), quorum)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot convert the share to additive")
	}
	c.sk = sk.Add(zeta).Value()
	c.pk[c.ctx.HolderID()] = c.suite.Curve().ScalarBaseMul(c.sk)
	c.keyed = true
	return nil
}

// AliceInput returns Alice's rVOLE input (r_i, sk_i), deriving the additive
// key share on first use.
func (c *Core[P, B, S]) AliceInput() ([]S, error) {
	if !c.committed {
		return nil, ErrRound.WithMessage("commit before deriving the input")
	}
	if err := c.keyShare(); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive the key share")
	}
	return []S{c.r, c.sk}, nil
}

// CheckValues stores Alice's output (c^u, c^v) of the rVOLE with id and
// returns the check values to send to Bob: Γ^u = c^u·G, Γ^v = c^v·G and
// ψ = φ_i − χ_{i,j}.
func (c *Core[P, B, S]) CheckValues(id sharing.ID, cShare []S) (*CheckValues[P, B, S], error) {
	chi, ok := c.chi[id]
	if !ok {
		return nil, ErrRound.WithMessage("no χ for party %d", id)
	}
	if len(cShare) != mulLength {
		return nil, ErrInvalidArgument.WithMessage("%d outputs, expected %d", len(cShare), mulLength)
	}
	c.c[id] = cShare
	return &CheckValues[P, B, S]{
		GammaU: c.suite.Curve().ScalarBaseMul(cShare[0]),
		GammaV: c.suite.Curve().ScalarBaseMul(cShare[1]),
		Psi:    c.phi.Sub(chi),
	}, nil
}

// Opening returns the opening of R_i and pk_i to broadcast, deriving the
// additive key share on first use.
func (c *Core[P, B, S]) Opening() (*Opening[P, B, S], error) {
	if !c.committed {
		return nil, ErrRound.WithMessage("commit before opening")
	}
	if err := c.keyShare(); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive the key share")
	}
	me := c.ctx.HolderID()
	return &Opening[P, B, S]{BigR: c.bigR[me], BigRWitness: c.bigRWitness, Pk: c.pk[me]}, nil
}

// ReceiveOpening verifies a counterparty's opening against its commitment,
// an identifiable abort attributed to id on failure, and stores R_j and pk_j.
func (c *Core[P, B, S]) ReceiveOpening(id sharing.ID, opening *Opening[P, B, S]) error {
	if err := ValidateOpening(opening); err != nil {
		return errs.Wrap(err).WithMessage("invalid opening from %d", id)
	}
	commitment, ok := c.bigRCommitment[id]
	if !ok {
		return ErrRound.WithMessage("no commitment from party %d", id)
	}
	if err := c.ck.Open(commitment, opening.BigR.ToCompressed(), opening.BigRWitness); err != nil {
		return errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid opening of R")
	}
	c.bigR[id] = opening.BigR
	c.pk[id] = opening.Pk
	return nil
}

// Verify checks Bob's output (d^u, d^v) of the rVOLE with id against the
// counterparty's check values, χ_{i,j}·R_j − Γ^u = d^u·G and
// χ_{i,j}·pk_j − Γ^v = d^v·G, an identifiable abort attributed to id on
// failure, and accumulates ψ and c + d for the partial signature. The opening
// of id must have been received first.
func (c *Core[P, B, S]) Verify(id sharing.ID, d []S, check *CheckValues[P, B, S]) error {
	if err := ValidateCheckValues(check); err != nil {
		return errs.Wrap(err).WithMessage("invalid check values from %d", id)
	}
	if len(d) != mulLength {
		return ErrInvalidArgument.WithMessage("%d outputs, expected %d", len(d), mulLength)
	}
	if c.verified[id] {
		return ErrRound.WithMessage("party %d already verified", id)
	}
	chi, ok := c.chi[id]
	if !ok {
		return ErrRound.WithMessage("no χ for party %d", id)
	}
	cShare, ok := c.c[id]
	if !ok {
		return ErrRound.WithMessage("no rVOLE output for party %d", id)
	}
	bigR, ok := c.bigR[id]
	if !ok {
		return ErrRound.WithMessage("no opening from party %d", id)
	}
	if !bigR.ScalarMul(chi).Sub(check.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
		return base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("instance key check failed")
	}
	if !c.pk[id].ScalarMul(chi).Sub(check.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
		return base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("key share check failed")
	}
	c.psi = c.psi.Add(check.Psi)
	c.cuDu = c.cuDu.Add(cShare[0].Add(d[0]))
	c.cvDv = c.cvDv.Add(cShare[1].Add(d[1]))
	c.verified[id] = true
	return nil
}

// Finish checks that the public-key shares add up to the public key, computes
// R = Σ_j R_j and
//
//	u_i = r_i(φ_i + Σ_j ψ_{j,i}) + Σ_j (c^u_{i,j} + d^u_{i,j}),
//	v_i = sk_i(φ_i + Σ_j ψ_{j,i}) + Σ_j (c^v_{i,j} + d^v_{i,j}),
//	w_i = H(m)·φ_i + r_x·v_i,
//
// and returns the partial signature (R, u_i, w_i). Every counterparty must
// have been verified. The aggregated nonce, r_x and H(m) are kept for the
// cosigning aggregator. Finish succeeds at most once per core.
func (c *Core[P, B, S]) Finish(message []byte) (*dkls23.PartialSignature[P, B, S], error) {
	if c.signed {
		return nil, ErrRound.WithMessage("already signed")
	}
	if !c.keyed {
		return nil, ErrRound.WithMessage("key share not derived")
	}
	for id := range c.ctx.OtherPartiesOrdered() {
		if !c.verified[id] {
			return nil, ErrRound.WithMessage("party %d not verified", id)
		}
	}

	bigR := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.bigR))...)
	pk := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.pk))...)
	if !pk.Equal(c.shard.PublicKey().Value()) {
		return nil, base.ErrAbort.WithMessage("public key check failed")
	}

	u := c.r.Mul(c.phi.Add(c.psi)).Add(c.cuDu)
	v := c.sk.Mul(c.phi.Add(c.psi)).Add(c.cvDv)
	digest, err := hashing.Hash(c.suite.HashFunc(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash the message")
	}
	m, err := ecdsa.DigestToScalar(c.suite.ScalarField(), digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert the digest to a scalar")
	}
	rxCoordinate, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot take the x-coordinate of R")
	}
	rx, err := c.suite.ScalarField().FromWideBytes(rxCoordinate.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert the x-coordinate to a scalar")
	}
	w := m.Mul(c.phi).Add(rx.Mul(v))

	partialSignature, err := dkls23.NewPartialSignature(bigR, u, w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the partial signature")
	}

	c.nonce = bigR
	c.rx = rx
	c.m = m
	c.message = message
	c.signed = true
	return partialSignature, nil
}

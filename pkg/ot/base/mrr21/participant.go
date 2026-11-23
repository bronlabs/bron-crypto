package mrr21

import (
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	protocolDomainSeparator = "BRON_CRYPTO-MRR21-%d-%d"
	msLabel                 = "BRON_CRYPTO-MRR21-MS-"
	phiLabel                = "BRON_CRYPTO-MRR21-PHI-"
	kaSaltLabel             = "BRON_CRYPTO-MRR21-KA-SALT-"
	kaSaltLength            = 32

	// MaxBatch bounds the batch length L. The key-agreement tag encodes the
	// instance index in 32 bits, and a batch costs one public-key operation
	// per OT anyway; the bound matches the extension's MaxExtension.
	MaxBatch = 1 << 20
)

// participant holds what both roles of the batched OT share: the two-party
// session and the counterparty's identifier, the prime-order group of the key
// agreement and the POPF, the batch length L (number of OTs, a positive
// multiple of 8 as in ot; the message length K is fixed by M), the
// randomness source, and the transcript inputs m_S and φ_1..φ_L once known.
type participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	copartyID sharing.ID
	group     algebra.PrimeGroup[G, S]
	l         int
	prng      io.Reader
	state     participantState[G, S]
}

type participantState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ms  G
	phi []*MasnyRindalPopf[G, S]
}

// newParticipant validates the common inputs of both roles: a non-nil session
// with exactly two parties, a non-nil group whose scalar structure is a prime
// field (exponents are sampled from it), L a positive multiple of 8 at most
// MaxBatch, and a
// non-nil prng, which must be cryptographically secure since it generates the
// secret exponents. The constructors of both roles then append the protocol's
// domain separator through appendDomainSeparator.
func newParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, group algebra.PrimeGroup[G, S], l int, prng io.Reader) (participant[G, S], error) {
	var nilParticipant participant[G, S]
	if ctx == nil {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("session context must not be nil")
	}
	if size := ctx.Quorum().Size(); size != 2 {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("quorum has %d parties, expected 2", size)
	}
	if utils.IsNil(group) {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("group must not be nil")
	}
	if _, ok := group.ScalarStructure().(algebra.PrimeField[S]); !ok {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("group scalar structure must be a prime field")
	}
	if l <= 0 || l%8 != 0 || l > MaxBatch {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("batch length L must be a positive multiple of 8 at most %d, got %d", MaxBatch, l)
	}
	if prng == nil {
		return nilParticipant, ot.ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	// The session guarantees its holder is in the quorum, so a quorum of two
	// leaves exactly one other party.
	return participant[G, S]{
		ctx:       ctx,
		copartyID: slices.Collect(ctx.OtherPartiesOrdered())[0],
		group:     group,
		l:         l,
		prng:      prng,
		state:     participantState[G, S]{}, //nolint:exhaustruct // populated during the protocol
	}, nil
}

// appendDomainSeparator appends the protocol's domain separator, parameterised
// by the message length K of M and the batch length L, to the session
// transcript, which the session already binds to its identifier. Both roles
// call it right after newParticipant so that their transcripts stay aligned.
func appendDomainSeparator[M ot.Message](ctx *session.Context, l int) {
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf(protocolDomainSeparator, ot.MessageBitLen[M](), l))
}

// updateTranscript binds m_S and every φ_i to the transcript, in the same order
// on both sides, before the key-agreement salt is extracted from it.
func (p *participant[G, S]) updateTranscript() {
	p.ctx.Transcript().AppendBytes(msLabel, p.state.ms.Bytes())

	phiBytes := sliceutils.Map(p.state.phi, func(m *MasnyRindalPopf[G, S]) []byte {
		return slices.Concat(m.s[0].Bytes(), m.s[1].Bytes())
	})
	p.ctx.Transcript().AppendBytes(phiLabel, phiBytes...)
}

// deriveKeyAgreementSalt extracts the HKDF salt of the key agreement from the
// transcript, so that every derived key is bound to the whole exchange.
func (p *participant[G, S]) deriveKeyAgreementSalt() ([]byte, error) {
	salt, err := p.ctx.Transcript().ExtractBytes(kaSaltLabel, kaSaltLength)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract key-agreement salt from transcript")
	}
	return salt, nil
}

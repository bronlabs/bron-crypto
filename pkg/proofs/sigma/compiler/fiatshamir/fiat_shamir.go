package fiatshamir

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	Name compiler.Name = "FiatShamir"

	transcriptLabel = "BRON_CRYPTO_NIZKP_FIATSHAMIR-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	a A
	z Z
}

type proofDTO[A sigma.Commitment, Z sigma.Response] struct {
	A A `cbor:"A"`
	Z Z `cbor:"Z"`
}

func (p *Proof[A, Z]) MarshalCBOR() ([]byte, error) {
	dto := &proofDTO[A, Z]{
		A: p.a,
		Z: p.z,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Fiat-Shamir proof")
	}
	return data, nil
}

func (p *Proof[A, Z]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*proofDTO[A, Z]](data)
	if err != nil {
		return err
	}
	p.a = dto.A
	p.z = dto.Z
	return nil
}

type fs[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func NewCompiler[
	X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response,
](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, errs.NewArgument("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}
	return &fs[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

func (c *fs[X, W, A, S, Z]) NewProver(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s-%s", sessionId, transcriptLabel, c.sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

func (c *fs[X, W, A, S, Z]) NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X, W], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s-%s", sessionId, transcriptLabel, c.sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

func (*fs[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

func (c *fs[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}

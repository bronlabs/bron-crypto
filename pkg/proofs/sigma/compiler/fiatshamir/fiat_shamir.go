package fiatshamir

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
	A A `json:"a"`
	Z Z `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*fs[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type fs[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func NewCompiler[
	X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response,
](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurity {
		return nil, errs.NewArgument("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurity)
	}
	return &fs[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

func (c *fs[X, W, A, S, Z]) NewProver(sessionId []byte, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sessionId), transcriptLabel, c.sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

func (c *fs[X, W, A, S, Z]) NewVerifier(sessionId []byte, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sessionId), transcriptLabel, c.sigmaProtocol.Name())
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

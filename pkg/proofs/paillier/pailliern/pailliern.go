package pailliern

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	appTranscriptLabel       = "KRYPTON_NIZK_PAILLIER_N"
	sessionIdTranscriptLabel = "KRYPTON_NIZK_PAILLIER_N_SESSION_ID"

	// Alpha ɑ.
	Alpha = 6370

	// M is defined as m = ⌈κ/log(ɑ)⌉, where κ = 128 and statistical soundness error is 2^(-κ).
	M = 11
)

// P is product of all primes < Alpha, the value is exported, so we can verify it in the tests.
var pBig, _ = new(big.Int).SetString("44871651744009136248115543081640547413785854417842050160655833875792914833852769205831424979368719986889519256934239452438251108738670217298542180982547421007901019408155961940142468907900676141149633188172029947498666222471142795699128314649438784106402197023949268047384343715946006767671319388463922366703585708460135453240679421061304864609915827908896062350138633849514905858373339528086006145373712431756746905467935232935398951226852071323775412278763371089401544920873813490290672436809231516731065356763193493525160238868779310055137922174496115680527519932793977258424479253973670103634070028863591207614649216492780891961054287421831028229266989697058385612003557825398202548657910983931484180193293615175594925895929359108723671212631368891689462486968022029482413912928883488902454913524492340322599922718890878760895105937402913873414377276608236656947832307175090505396675623505955607363683869194683635689701238311577953994900734498406703176954324494694474545570839360607926610248093452739817614097197031607820417729009847465138388398887861935127785385309564525648905444610640901769290645369888935446477559073843982605496992468605588284307311971153579731703863970674466666844817336319390617551354845025116350295041840093627836067370100384861820888752358520276041000456608056339377573485917445104757987800101659688183150320442308091835974182809184299472568260682774683272697993855730500061223160274918361373258473553412704497335663924406111413972911417644029226449602417135116011968946232623154008710271296183350215563946003547561056456285939676838623311370087238225630994506113422922846572616538637723054222166159389475617214681282874373185283568512603887750846072033376432252677883915884203823739988948315257311383912016966925295975180180438969999175030785077627458887411146486902613291202008193902979800279637509789564807502239686755727063367075758492823731724669702442450502667810890608807091448688985203084972035197770874223259420649055450382725355162738490355628688943706634905982449810389530661328557381850782677221561924983234877936783136471890539395124220965982831778882400224156689487137227198030461624542872774217771594215907203725682315714199249588874271661233929713660269883273404764648327455796699366900022345171030564747210542398285078804310752063852249740561571105640741618793118627170070315410588646442647771802031066589341358879304845579387079972404386434238273904239604603511925708377008467129590636257287965232576327580009018475271364237665836186806027331208426256451429549641988386585949300254487647395222785274120561299318070944530096970076560461229486504018773252771360855091191876004370694539453020462096690084476681253865429278552786361828508910022714749051734108364178374765700925133405508684883070", 10)
var P = new(saferith.Nat).SetBig(pBig, pBig.BitLen())

type Proof struct {
	Sigmas []*saferith.Nat
}

type Prover struct {
	sessionId  []byte
	transcript transcripts.Transcript
}

func NewProver(sessionId []byte, transcript transcripts.Transcript) (prover *Prover, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewIsNil("sessionId")
	}

	return &Prover{
		sessionId:  sessionId,
		transcript: transcript,
	}, nil
}

func (p *Prover) Prove(witness *paillier.SecretKey) (proof *Proof, statement *paillier.PublicKey, err error) {
	if witness == nil {
		return nil, nil, errs.NewIsNil("witness")
	}

	transcript := p.transcript
	if transcript == nil {
		transcript = hagrid.NewTranscript(appTranscriptLabel, nil)
	}
	transcript.AppendMessages(sessionIdTranscriptLabel, p.sessionId)

	rhos, err := extractRhos(transcript, witness.GetNModulus())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create a proof")
	}

	phi := saferith.ModulusFromNat(witness.Phi)
	nInv := new(saferith.Nat).ModInverse(witness.N, phi)
	sigmas := make([]*saferith.Nat, M)
	for i, rho := range rhos {
		sigmas[i] = bignum.FastExpCrt(witness.GetCrtNParams(), rho, nInv, witness.GetNModulus())
	}

	proof = &Proof{
		Sigmas: sigmas,
	}
	return proof, &witness.PublicKey, nil
}

func Verify(sessionId []byte, transcript transcripts.Transcript, statement *paillier.PublicKey, proof *Proof) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId")
	}
	if statement == nil {
		return errs.NewIsNil("statement")
	}
	if proof == nil {
		return errs.NewIsNil("proof")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(appTranscriptLabel, nil)
	}
	transcript.AppendMessages(sessionIdTranscriptLabel, sessionId)

	rhos, err := extractRhos(transcript, statement.GetNModulus())
	if err != nil {
		return errs.WrapFailed(err, "cannot verify a proof")
	}

	if statement.N.Coprime(P) != 1 {
		return errs.NewVerification("verification failed")
	}

	if len(proof.Sigmas) != M {
		return errs.NewVerification("verification failed")
	}

	for i, sigma := range proof.Sigmas {
		rhoCheck := bignum.FastExp(sigma, statement.N, statement.N)
		if _, eq, _ := rhoCheck.Cmp(rhos[i]); eq != 1 {
			return errs.NewVerification("verification failed")
		}
	}

	return nil
}

func extractRhos(transcript transcripts.Transcript, n *saferith.Modulus) ([]*saferith.Nat, error) {
	byteSize := uint((n.BitLen() + 7) / 8)
	excessBits := n.BitLen() % 8

	result := make([]*saferith.Nat, M)
	for i := 0; i < M; i++ {
		for k := 0; k < 128; k++ {
			label := fmt.Sprintf("rho_%d_%d", i, k)
			candidateBytes, err := transcript.ExtractBytes(label, byteSize)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot extract rho")
			}

			candidateBytes[0] &= (1 << excessBits) - 1 // candidateBytes[0] is the highest byte (big endian)
			candidateNat := new(saferith.Nat).SetBytes(candidateBytes)

			// we are rejecting a candidate rho >= N,
			// instead of rejecting we could just do rho mod N, but this would introduce slightly biased value.
			_, _, l := candidateNat.Cmp(n.Nat())
			if candidateNat.Coprime(n.Nat()) == 1 && l == 1 {
				result[i] = candidateNat
				break
			}
		}

		// probability of this happening is very low (< 2^(-128))
		if result[i] == nil {
			return nil, errs.NewFailed("cannot find suitable rho")
		}
	}

	return result, nil
}

package testutils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/nist"
)

const (
	// Test file names.
	FileDRGBVectorsNoReseed = "testutils/drbgtestvectors/drbgvectors_no_reseed/CTR_DRBG.rsp"
	FILEDRGBVectorsPRFalse  = "testutils/drbgtestvectors/drbgvectors_pr_false/CTR_DRBG.rsp"
	// Test file constants.
	testHeaderLine = "[AES-%d %s df]" // Indicates the beginning of a new AES-based test
	maxTestCount   = 14               // Number of tests per case
)

/*.--------------------------- NIST Test Helper -----------------------------.*/

// NistTestConfig contains the configuration of a set NIST test cases to be scanned.
type NistTestConfig struct {
	PredictionResistance     bool
	EntropyInputLen          int
	NonceLen                 int
	PersonalizationStringLen int
	AdditionalInputLen       int
	ReturnedBitsLen          int
}

// NistTestCase contains the state of a NIST test case.
type NistTestCase struct {
	Count                 int
	EntropyInput          []byte
	Nonce                 []byte
	PersonalizationStr    []byte
	EntropyInputReseed    []byte
	AdditionalInputReseed []byte
	AdditionalInput1      []byte
	AdditionalInput2      []byte
	ReturnedBits          []byte
}

func NewNistTestCase(config *NistTestConfig) *NistTestCase {
	return &NistTestCase{
		Count:                 0,
		EntropyInput:          make([]byte, (config.EntropyInputLen >> 3)),
		Nonce:                 make([]byte, (config.NonceLen >> 3)),
		PersonalizationStr:    make([]byte, (config.PersonalizationStringLen >> 3)),
		EntropyInputReseed:    make([]byte, (config.EntropyInputLen >> 3)),
		AdditionalInputReseed: make([]byte, (config.AdditionalInputLen >> 3)),
		AdditionalInput1:      make([]byte, (config.AdditionalInputLen >> 3)),
		AdditionalInput2:      make([]byte, (config.AdditionalInputLen >> 3)),
		ReturnedBits:          make([]byte, (config.ReturnedBitsLen >> 3)),
	}
}

type NistTestHelper struct {
	// Fixed test parameters
	AesKeySize    int
	UseDf         bool
	isNewTestExpr string

	Config *NistTestConfig // Scanned test config
	State  *NistTestCase   // Scanned test state

	FileScanner *bufio.Scanner

	// Internal Counters
	LineNo  int
	TestNo  int
	CountNo int
}

// NewNistTestHelper creates a new NistTestHelper instance for the given file. The test
// parameters are fixed for the entire file:
//   - AesKeySize: {128, 192, 256}
//   - UseDf: {true, false}
func NewNistTestHelper(f *os.File, AesKeySize int, UseDf bool) *NistTestHelper {
	return &NistTestHelper{
		AesKeySize: AesKeySize,
		UseDf:      UseDf,
		isNewTestExpr: fmt.Sprintf(testHeaderLine,
			AesKeySize,
			map[bool]string{true: "use", false: "no"}[UseDf]),
		Config: &NistTestConfig{
			PredictionResistance:     false,
			EntropyInputLen:          0,
			NonceLen:                 0,
			PersonalizationStringLen: 0,
			AdditionalInputLen:       0,
			ReturnedBitsLen:          0,
		},
		State:       nil,
		FileScanner: bufio.NewScanner(f),
		LineNo:      0,
		TestNo:      0,
		CountNo:     0,
	}
}

// Scan advances the Scanner to the next line. Returns false if it reaches EOF.
func (nistTest *NistTestHelper) Scan() bool {
	scanResult := nistTest.FileScanner.Scan()
	nistTest.LineNo++
	return scanResult
}

// IsNewTestCase returns true if the current line is the start of a new test. Example
// of a new test line:
//
//	[AES-256, use df]
func (nistTest *NistTestHelper) IsNewTestCase() bool {
	return nistTest.FileScanner.Text() == nistTest.isNewTestExpr
}

// Sscanf scans the current line and parses it according to the format string.
func (nistTest *NistTestHelper) Sscanf(canBeEmpty bool, format string, a ...any) error {
	scanResult := nistTest.FileScanner.Scan()
	nistTest.LineNo++
	if !scanResult && !canBeEmpty {
		return errs.New("Expected line %d not to be empty", nistTest.LineNo)
	}
	line := nistTest.FileScanner.Text()
	fixedPartMatches := (format == "") || (line == format[:len(format)-2]) // -2 to remove the %d|%x
	_, err := fmt.Sscanf(line, format, a...)
	if err != nil && (!canBeEmpty || !fixedPartMatches) {
		return errs.New("Error parsing line %d: %s", nistTest.LineNo, err)
	}
	return nil
}

// ScanTestConfig reads the test configuration from the current line.
// An example of a test configuration is:
//
//	[PredictionResistance = False]
//	[EntropyInputLen = 256]
//	[NonceLen = 128]
//	[PersonalizationStringLen = 0]
//	[AdditionalInputLen = 0]
//	[ReturnedBitsLen = 512]
func (nistTest *NistTestHelper) ScanTestConfig() error {
	if err := nistTest.Sscanf(false, "[PredictionResistance = %t]", &nistTest.Config.PredictionResistance); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "[EntropyInputLen = %d]", &nistTest.Config.EntropyInputLen); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "[NonceLen = %d]", &nistTest.Config.NonceLen); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "[PersonalizationStringLen = %d]", &nistTest.Config.PersonalizationStringLen); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "[AdditionalInputLen = %d]", &nistTest.Config.AdditionalInputLen); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "[ReturnedBitsLen = %d]", &nistTest.Config.ReturnedBitsLen); err != nil {
		return errs.Wrap(err)
	}
	// Scan the empty line after the test config
	if !nistTest.Scan() {
		return errs.New("Expected line %d not to be empty", nistTest.LineNo)
	}
	// Initialise test state
	nistTest.State = NewNistTestCase(nistTest.Config)
	return nil
}

// ScanTestCase reads the test case from the current line. An example of a test
// case is:
//
//	COUNT = 0
//	EntropyInput = 36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14
//	Nonce = 496f25b0f1301b4f501be30380a137eb
//	PersonalizationString =
//	AdditionalInput =
//	AdditionalInput =
//	ReturnedBits = 5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d
func (nistTest *NistTestHelper) ScanTestCase(withReseed bool) error {
	if err := nistTest.Sscanf(false, "COUNT = %d", &nistTest.State.Count); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "EntropyInput = %x", &nistTest.State.EntropyInput); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "Nonce = %x", &nistTest.State.Nonce); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(true, "PersonalizationString = %x", &nistTest.State.PersonalizationStr); err != nil {
		return errs.Wrap(err)
	}
	if withReseed {
		if err := nistTest.Sscanf(true, "EntropyInputReseed = %x", &nistTest.State.EntropyInputReseed); err != nil {
			return errs.Wrap(err)
		}
		if err := nistTest.Sscanf(true, "AdditionalInputReseed = %x", &nistTest.State.AdditionalInputReseed); err != nil {
			return errs.Wrap(err)
		}
	}
	if err := nistTest.Sscanf(true, "AdditionalInput = %x", &nistTest.State.AdditionalInput1); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(true, "AdditionalInput = %x", &nistTest.State.AdditionalInput2); err != nil {
		return errs.Wrap(err)
	}
	if err := nistTest.Sscanf(false, "ReturnedBits = %x", &nistTest.State.ReturnedBits); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

/*.------------------------- PRNG Run Methods -------------------------------.*/
// RunInit initialises a prng with the current test case.
func (nistTest *NistTestHelper) RunInit(AesKeySize int) (*nist.PrngNist, error) {
	if nistTest.State.Count != nistTest.CountNo {
		return nil, errs.New("TestState.Count != CountNo (%d != %d)", nistTest.State.Count, nistTest.CountNo)
	}
	prng, err := nist.NewNistPRNG(AesKeySize, nil, nistTest.State.EntropyInput, nistTest.State.Nonce, nistTest.State.PersonalizationStr)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return prng, nil
}

// RunGenerate generates the next `len(buffer)` random bytes using `aditionalInput`
// and stores them in `buffer`.
func (nistTest *NistTestHelper) RunGenerate(prng *nist.PrngNist, buffer []byte) error {
	if err := prng.Generate(buffer, nistTest.State.AdditionalInput1); err != nil {
		return errs.Wrap(err)
	}
	if err := prng.Generate(buffer, nistTest.State.AdditionalInput2); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// RunReseed seeds the prng with the provided entropy and the additional input.
func (nistTest *NistTestHelper) RunReseed(prng *nist.PrngNist, buffer []byte) error {
	if err := prng.Reseed(nistTest.State.EntropyInputReseed, nistTest.State.AdditionalInputReseed); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// RunRead reads the next `len(buffer)` random bytes and stores them in `buffer`.
func (*NistTestHelper) RunRead(prng *nist.PrngNist, buffer []byte) error {
	if _, err := io.ReadFull(prng, buffer); err != nil {
		return errs.Wrap(err)
	}
	if _, err := io.ReadFull(prng, buffer); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

/*.----------------------- Nist Test Run Methods ----------------------------.*/
// RunNistTestCases runs the NIST test suite for the given file and parameters.
func RunNistTestCases(f *os.File, AesKeySize int, useDf, withReseed bool) error {
	nistTest := NewNistTestHelper(f, AesKeySize, useDf)
	for nistTest.Scan() {
		if nistTest.IsNewTestCase() {
			// Scan test config
			if err := nistTest.ScanTestConfig(); err != nil {
				return errs.Wrap(err)
			}
			returnedBits := make([]byte, nistTest.Config.ReturnedBitsLen/8)

			for nistTest.CountNo = 0; nistTest.CountNo < maxTestCount; nistTest.CountNo++ {
				// Scan test state
				if err := nistTest.ScanTestCase(withReseed); err != nil {
					return errs.Wrap(err)
				}
				// Run initialisation
				prng, err := nistTest.RunInit(AesKeySize)
				if err != nil {
					return errs.Wrap(err)
				}
				// Run reseed
				if withReseed {
					if err := nistTest.RunReseed(prng, returnedBits); err != nil {
						return errs.Wrap(err)
					}
				}
				// Run generation
				if err := nistTest.RunGenerate(prng, returnedBits); err != nil {
					return errs.Wrap(err)
				}
				// Check test results
				if !bytes.Equal(nistTest.State.ReturnedBits, returnedBits) {
					return errs.Wrap(err)
				}
				// Scan empty line
				if err := nistTest.Sscanf(true, ""); err != nil {
					return errs.Wrap(err)
				}
			}
			nistTest.TestNo++
		}
	}
	return nil
}

// RunNistValidationTest runs the NIST test suite for both the seeded and non-seeded cases.
func RunNistValidationTest(keySize int, useDf bool) (err error) {
	for _, caseParams := range []struct {
		withReseed bool
		fName      string
	}{
		{withReseed: false, fName: FileDRGBVectorsNoReseed},
		{withReseed: true, fName: FILEDRGBVectorsPRFalse},
	} {
		// Open test data file
		f, err := os.Open(caseParams.fName)
		if err != nil {
			return errs.Wrap(err)
		}
		// Run tests
		if err := RunNistTestCases(f, keySize, useDf, caseParams.withReseed); err != nil {
			return errs.Wrap(err)
		}
		// Close test data file
		if err := f.Close(); err != nil {
			return errs.Wrap(err)
		}
	}
	return nil
}

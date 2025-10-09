package dudect_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/tools/dudect"
)

func ExamplePaillierAnalysis() {
	// Generate Paillier keys
	kg := &paillier.KeyGenerator{}
	sk, pk, err := kg.Generate(rand.Reader)
	if err != nil {
		panic(err)
	}

	dec := paillier.NewDecrypter(sk)
	enc := paillier.NewEncrypter()

	// Create test ciphertexts
	var smallPlaintext numct.Nat
	smallPlaintext.SetBytes([]byte{0x01})
	smallCiphertext, _, _ := enc.Encrypt((*paillier.Plaintext)(&smallPlaintext), pk, rand.Reader)

	largePlaintext := pk.N().Nat().Clone()
	largePlaintext.Decrement()
	largeCiphertext, _, _ := enc.Encrypt((*paillier.Plaintext)(largePlaintext), pk, rand.Reader)

	// Configure analysis
	cfg := dudect.Config{
		Target:            "Paillier.Decrypt",
		NMeasures:         200,
		TargetNsPerSample: 10000000,
		EarlyStop:         true, // Enable early stopping
	}

	// Build test function
	build := func(cls byte, i int, rng *dudect.Rand) func() {
		var ct *paillier.Ciphertext
		if cls == 0 {
			ct = smallCiphertext
		} else {
			ct = largeCiphertext
		}
		return func() {
			_, _ = dec.Decrypt(ct)
		}
	}

	// Run analysis
	result := dudect.Run(build, cfg)
	
	if result.Leak {
		fmt.Printf("Timing leak detected: max|t|=%.2f\n", result.MaxT)
	} else {
		fmt.Printf("No timing leak detected: max|t|=%.2f\n", result.MaxT)
	}
}

func TestPaillierDecrypt(t *testing.T) {
	// Generate keys
	kg := &paillier.KeyGenerator{}
	sk, pk, err := kg.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dec := paillier.NewDecrypter(sk)
	enc := paillier.NewEncrypter()

	// Create test inputs
	var smallPlaintext numct.Nat
	smallPlaintext.SetBytes([]byte{0x01})
	smallCiphertext, _, _ := enc.Encrypt((*paillier.Plaintext)(&smallPlaintext), pk, rand.Reader)

	largePlaintext := pk.N().Nat().Clone()
	largePlaintext.Decrement()
	largeCiphertext, _, _ := enc.Encrypt((*paillier.Plaintext)(largePlaintext), pk, rand.Reader)

	// Configure with early stopping
	cfg := dudect.Config{
		Target:            "Paillier.Decrypt",
		NMeasures:         500,
		TargetNsPerSample: 10000000,
		EarlyStop:         true,
	}

	build := func(cls byte, i int, rng *dudect.Rand) func() {
		var ct *paillier.Ciphertext
		if cls == 0 {
			ct = smallCiphertext
		} else {
			ct = largeCiphertext
		}
		return func() {
			_, _ = dec.Decrypt(ct)
		}
	}

	// Run preflight checks
	report, tunedCfg := dudect.Preflight(build, cfg)
	t.Log(report.String())

	// Run analysis
	result := dudect.Run(build, tunedCfg)
	
	t.Logf("Results: max|t|=%.3f (threshold=%.1f) leak=%v", 
		result.MaxT, result.Threshold, result.Leak)
	
	if result.EarlyStopped {
		t.Logf("Analysis stopped early at %d measurements", result.StoppedAt)
	}
	
	// We expect decrypt to be constant-time
	if result.Leak {
		t.Errorf("Paillier.Decrypt shows timing leak: max|t|=%.3f", result.MaxT)
	}
}

func TestPaillierPhi(t *testing.T) {
	// Generate keys
	kg := &paillier.KeyGenerator{}
	_, pk, err := kg.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create test inputs
	var smallPlaintext numct.Nat
	smallPlaintext.SetBytes([]byte{0x01})
	
	largePlaintext := pk.N().Nat().Clone()
	largePlaintext.Decrement()

	cfg := dudect.Config{
		Target:            "Paillier.Phi",
		NMeasures:         5000,
		TargetNsPerSample: 5000,
		EarlyStop:         true,
	}

	build := func(cls byte, i int, rng *dudect.Rand) func() {
		var pt *paillier.Plaintext
		if cls == 0 {
			pt = (*paillier.Plaintext)(&smallPlaintext)
		} else {
			pt = (*paillier.Plaintext)(largePlaintext)
		}
		return func() {
			_ = paillier.Phi(pk, pt)
		}
	}

	result := dudect.Run(build, cfg)
	
	t.Logf("Results: max|t|=%.3f (threshold=%.1f) leak=%v", 
		result.MaxT, result.Threshold, result.Leak)
	
	// We expect Phi to leak timing
	if !result.Leak {
		t.Errorf("Expected Paillier.Phi to show timing leak but none detected: max|t|=%.3f", result.MaxT)
	}
}
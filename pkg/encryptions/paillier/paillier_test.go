package paillier_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
)

var (
	zero      = nat("0")
	one       = nat("1")
	two       = nat("2")
	x         = nat("7146643783615963513942641287213372249533955323510461217840179896547799100626220786140425637990097431")
	y         = nat("1747698065194620177681258504464368264357359841192790848951902311522815739310792522712583635858354245")
	n         = nat("85832751158419329546684678412285185885848111422509523329716452068504806021136687603399722116388773253")
	nMinusOne = new(saferith.Nat).Sub(n, one, -1)
	nPlusOne  = new(saferith.Nat).Add(n, one, -1)

	nn         = new(saferith.Nat).Mul(n, n, -1)
	nnMinusOne = new(saferith.Nat).Sub(nn, one, -1)
	nnPlusOne  = new(saferith.Nat).Add(nn, one, -1)
)

type keygenTest struct {
	bits             int
	p, q, n, totient *saferith.Nat
}

func Example_encryptDecrypt() {
	hexMessage := strings.ToUpper(hex.EncodeToString([]byte("Hello World!")))
	mappedMessage, err := new(saferith.Nat).SetHex(hexMessage)
	if err != nil {
		panic(err)
	}
	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	// Ignoring the random value that was generated internally by `Encrypt`.
	cipher, _, err := pub.Encrypt(mappedMessage, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	// Now decrypt using the secret key.
	decryptor, err := paillier.NewDecryptor(sec)
	if err != nil {
		log.Fatalf("Error in creating decryptor: %v", err)
	}
	decrypted, err := decryptor.Decrypt(cipher)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}

	decoded := string(decrypted.Big().Bytes())
	fmt.Println("Succeeded in encrypting and decrypting the input message:", decoded)

	// Output:
	// Succeeded in encrypting and decrypting the input message: Hello World!
}

func Example_homomorphicAddition() {
	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := nat("123")
	msg2 := nat("456")
	fmt.Printf("Encrypting %s and %s separately.\n", msg1.Big().String(), msg2.Big().String())

	cipher1, _, err := pub.Encrypt(msg1, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}
	cipher2, _, err := pub.Encrypt(msg2, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Println("Adding their encrypted versions together.")
	cipher3, err := pub.Add(cipher1, cipher2)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}
	decryptor, err := paillier.NewDecryptor(sec)
	if err != nil {
		log.Fatalf("Error in creating decryptor: %v", err)
	}
	decrypted3, err := decryptor.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Println("Succeeded in decrypting", decrypted3.Big().String())

	// Output:
	// Encrypting 123 and 456 separately.
	// Adding their encrypted versions together.
	// Succeeded in decrypting 579
}

func Example_homomorphicMultiplication() {
	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := nat("10")
	msg2 := nat("5")
	fmt.Printf("Encrypting %s.\n", msg1.Big().String())

	cipher1, _, err := pub.Encrypt(msg1, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Printf("Multiplying plain %s with the encrypted %s.\n", msg2.Big().String(), msg1.Big().String())
	cipher3, err := pub.MulPlaintext(cipher1, msg2)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}
	decryptor, err := paillier.NewDecryptor(sec)
	if err != nil {
		log.Fatalf("Error in creating decryptor: %v", err)
	}
	decrypted3, err := decryptor.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Printf("Succeeded in decrypting %s.\n", decrypted3.Big().String())

	// Output:
	// Encrypting 10.
	// Multiplying plain 5 with the encrypted 10.
	// Succeeded in decrypting 50.
}

func TestKeyGen(t *testing.T) {
	testValues := []*keygenTest{
		{
			bits:    32,
			p:       nat("2404778303"),
			q:       nat("2907092159"),
			n:       nat("6990912148784626177"),
			totient: nat("6990912143472755716"),
		},
		// Moderate values
		{
			bits:    256,
			p:       nat("115645895734860215235155088728394909334688633450524492586690742412129345961183"),
			q:       nat("94298418052417649431120534110853375174108454456092458684756344618179781451887"),
			n:       nat("10905225022052151768592443014939079805820716955892154646109970627753805040740378163517568530133182652794506558827042053659527293884287341299235199284102321"),
			totient: nat("10905225022052151768592443014939079805820716955892154646109970627753805040740168219203781252268516377171667310542533256571620676933015894212204890156689252"),
		},
		{
			bits:    384,
			p:       nat("36006692832910486705531921197379033634897461505036495703751117530881437756504623602114452424392242359949564580091963"),
			q:       nat("36321876854655342367765793082986061200135195654801162378979445503936881469720608843798409137541849432902150243071007"),
			n:       nat("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253561264090635848856642357599288411446282200143037556882504679979558002244844355483553171478292766242112114935599016741"),
			totient: nat("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253488935520948283027569059885008046351447167485877719224421949416523183925618130251107258616730832150319263220775853772"),
		},
		// Large values
		{
			bits:    512,
			p:       nat("13334877681824046536664719753000692481615243060546695171749157112026072862294410162436291925578885141357927002155461724765584886877402066038258074266638227"),
			q:       nat("12122745362522189816168535264551355768089283231069686330301128627041958196835868405970767150401427191976786435200511843851744213149595052566013030642866907"),
			n:       nat("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858500001631307112890860155944955185080369964944108396477646372269079498823545159135772467319334869864305928043113234061678778620562861360302446649667820279453889"),
			totient: nat("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858499976173684068544623803111700167528321715239582104861264870218793759755514100005493898912275793883993594708399796705705210003233761333305328045396715369948756"),
		},
		{
			bits:    768,
			p:       nat("1346090925391135119143470623782502005582449208798686393499686094146720873293257316154858443761764176763426496081748327594475673914483978883075080616518148610864446133054517784818794038700373924492201179029136162262578223994386497407"),
			q:       nat("1267888740317619255987103204389173685200460862251480292534873171503916906509928280188817985770625788023592223617980306560361856737457586891910981446078699966027435065022526191471061668427090194699255004927681350300606724099539148139"),
			n:       nat("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565327188316266582808161080083810509077419565819105286361318424233748287133200189491965280880943430756926385486914657888021988499576975592342792662208243895780558951878131107691067112167457219510292850345325644694079605526537816712375573"),
			totient: nat("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565324574336600874053785949509982337401728782909034236194632389674482636495420386306368937204513898366961598468194958159387833662046323650777017676146181298931982059996933030647090822311750092046173658889141687876567042341589722786730028"),
		},
		{
			bits:    1024,
			p:       nat("323048346478810234804346724288317979049543453886657577003300101860710127877799870550562838407667268404599358826513829060160504303395418566677040422188661745067470888457815635033321184439746580337024906877384167362567610372271431186610013379997212856608697550064099211785613236213633622219571487990672693003787"),
			q:       nat("289955956844872723713267618282085026937397801221604643862282902289352466511076698253093993268863225914839327563609168378629851975959785812001060859728689670901677697805606458924299545852498153652948060776824445669854015488773545309215892532182626763404124068861635361632889336491051975303142403383113070034867"),
			n:       nat("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531738646998208894219436266840478325951526823776791414200683451217351791095609379048292074062880637329062218371522375097661526583290635879391529194601725476785472157424230313351359992497803391595095260449578824637692631790170131436072668730121222036510650215208397389118631464109460927478825133780143983053041329"),
			totient: nat("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531125642694885211260918652497907922945539882521683151979817868213201728501220502479488417231204106834742779685132252100222736227011280675012851093319808125369503008837966891257402371767511146861105287481924616024660210164309086459576842824209042196890637393589471654545212961536756241881302419888770197290002676"),
		},
	}

	for i, test := range testValues {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			safePrimes := []*saferith.Nat{theTest.p, theTest.q}
			f := func(bits int, reader io.Reader) (*saferith.Nat, *saferith.Nat, error) {
				return safePrimes[0], safePrimes[1], nil
			}

			pub, sec, err := paillier.KeyGenWithPrimeGenerator(theTest.bits, crand.Reader, f)
			require.NoError(t, err)
			require.Equal(t, pub.N.Eq(theTest.n), saferith.Choice(1))
			require.Equal(t, sec.Phi.Eq(theTest.totient), saferith.Choice(1))
		})
	}
}

func TestGenerateSafePrimes(t *testing.T) {
	p, err := primes.GenerateSafePrime(32)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.Big().ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
	p, err = primes.GenerateSafePrime(3)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.Big().ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
}

func TestGenerateSafePrimesLong(t *testing.T) {
	const bits = 1024

	if testing.Short() {
		t.Skip("Skipping GenerateSafePrimesLong")
	}
	p, err := primes.GenerateSafePrime(bits)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.Big().ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
	if p.TrueLen() != bits {
		t.Errorf("GenerateSafePrime didn't return a prime number with the exact bits")
	}
}

func TestGenerateSafePrimesTooLow(t *testing.T) {
	_, err := primes.GenerateSafePrime(2)
	require.Error(t, err)
}

type lcmTest struct {
	x *saferith.Nat
	y *saferith.Nat

	_ ds.Incomparable
}

func TestKeyGeneratorErrorConditions(t *testing.T) {
	// Should fail if a safe prime cannot be generated.
	f := func(bits int, reader io.Reader) (*saferith.Nat, *saferith.Nat, error) {
		return nil, nil, fmt.Errorf("safeprime error")
	}
	_, _, err := paillier.KeyGenWithPrimeGenerator(1, crand.Reader, f)
	require.Contains(t, err.Error(), "safeprime error")

	// Should fail if a gcd of p and q is zero.
	val := uint64(0)
	oneF := func(bits int, reader io.Reader) (*saferith.Nat, *saferith.Nat, error) {
		p := new(saferith.Nat).SetUint64(val)
		q := new(saferith.Nat).SetUint64(val + 1)
		val += 2
		return p, q, nil
	}
	_, _, err = paillier.KeyGenWithPrimeGenerator(1, crand.Reader, oneF)
	require.True(t, errs.IsFailed(err))
}

func TestNewKeysDistinct(t *testing.T) {
	pub1, sec1, err := paillier.KeyGen(1024, crand.Reader)
	require.NoError(t, err)
	pub2, sec2, err := paillier.KeyGen(1024, crand.Reader)
	require.NoError(t, err)
	// Ensure two fresh keys are distinct
	require.True(t, pub1.N.Eq(pub2.N) == 0)
	require.True(t, sec1.Phi.Eq(sec2.Phi) == 0)
	require.True(t, sec1.GetMu().Eq(sec2.GetMu()) == 0)
}

// Tests the restrictions on input values for paillier.Add
func TestAddErrorConditions(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)

	tests := []struct {
		x, y         *saferith.Nat
		expectedPass bool
	}{
		// Good: 0 ≤ x,y < N²
		{nMinusOne, nat("1024"), true}, // N-1, 1024
		{one, nnMinusOne, true},        // one, N²-1

		{zero, one, false}, // x is zero
		{nil, one, false},  // x nil
		{one, nil, false},  // y nil

		{nnPlusOne, one, false},                         // N²+1
		{nnPlusOne, nnPlusOne, false},                   // both bad
		{one, nnPlusOne, false},                         // N²+1
		{new(saferith.Nat).Add(nn, nn, -1), one, false}, // 2N²
		{one, new(saferith.Nat).Add(nn, nn, -1), false}, // 2N²
		{nn, one, false},                                // = N²
		{one, nn, false},                                // = N²
	}

	// All the tests!
	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := pk.Add(&paillier.CipherText{C: theTest.x}, &paillier.CipherText{C: theTest.y})
			if theTest.expectedPass {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSubPlaintext(t *testing.T) {
	pk, sk, err := paillier.KeyGen(128, crand.Reader)
	require.NoError(t, err)

	tests := []struct {
		x, y, expected uint64
	}{
		{x: 1, y: 1, expected: 0},
		{x: 75824, y: 8326, expected: 67498},
		{x: 985739, y: 185635, expected: 800104},
		{x: 234623, y: 234622, expected: 1},
		{x: 567295, y: 393645, expected: 173650},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d - %d = %d", test.x, test.y, test.expected), func(t *testing.T) {
			encryptedX, _, err := pk.Encrypt(new(saferith.Nat).SetUint64(test.x), crand.Reader)
			require.NoError(t, err)
			zEncrypted, err := pk.SubPlaintext(encryptedX, new(saferith.Nat).SetUint64(test.y))
			require.NoError(t, err)
			decryptor, err := paillier.NewDecryptor(sk)
			require.NoError(t, err)
			z, err := decryptor.Decrypt(zEncrypted)
			require.NoError(t, err)
			require.Equal(t, test.expected, z.Uint64())
		})
	}
}

// Tests for paillier addition with known answers
func TestAdd(t *testing.T) {
	z9, err := paillier.NewPublicKey(new(saferith.Nat).SetUint64(3))
	require.NoError(t, err)
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)

	// Pre-compute values for testing
	z := new(saferith.Nat).Add(n, n, -1)
	z = new(saferith.Nat).Add(z, one, -1)

	tests := []struct {
		pk             *paillier.PublicKey
		x, y, expected *saferith.Nat
	}{
		// Small number tests: Z_9
		// {z9, parseNat("0"), parseNat("1"), parseNat("0")},
		{z9, nat("1"), nat("5"), nat("5")},
		{z9, nat("2"), nat("2"), nat("4")},
		{z9, nat("5"), nat("2"), nat("1")},
		{z9, nat("7"), nat("7"), nat("4")},
		{z9, nat("2"), nat("4"), nat("8")},
		{z9, nat("8"), nat("8"), nat("1")},
		{z9, nat("8"), nat("2"), nat("7")},

		// large number tests: Z_N²
		// {pk, n, zero, zero},
		// {pk, zero, nPlusOne, zero},
		{pk, nPlusOne, nPlusOne, z}, // (N+1)² = N² + 2N + 1 ≡ 2N + 1 (N²)
		{pk, nat("11659564086467828628"), nat("57089538512338875950"), nat("665639132951488346363609789106750696600")},
	}
	// All the tests!
	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			actual, err := test.pk.Add(&paillier.CipherText{C: theTest.x}, &paillier.CipherText{C: theTest.y})
			require.NoError(t, err)
			require.NotZero(t, theTest.expected.Eq(actual.C))
		})
	}
}

// Tests the restrictions on input values for paillier.Mul
func TestMulErrorConditions(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)

	tests := []struct {
		x, y            *saferith.Nat
		expectedPass    bool
		expectedErrFunc func(error) bool
	}{
		// Good
		{zero, one, true, nil},              // 0 ≤ x,y < N
		{nMinusOne, nat("1024"), true, nil}, // 0 ≤ x,y < N
		{one, nnMinusOne, true, nil},        // 1 < N; N²-1 < N

		{nPlusOne, one, false, errs.IsArgument},                          // x > N; y ok
		{nPlusOne, nnPlusOne, false, errs.IsArgument},                    // both x,y bad
		{one, nnPlusOne, false, errs.IsArgument},                         // y bad
		{new(saferith.Nat).Add(nn, nn, -1), one, false, errs.IsArgument}, // x really bad
		{one, new(saferith.Nat).Add(nn, nn, -1), false, errs.IsArgument}, // y bad
		{n, one, false, errs.IsArgument},                                 // x boundary condition
		{one, nn, false, errs.IsArgument},                                // y boundary condition
		{nil, one, false, errs.IsIsNil},                                  // x nil
		{one, nil, false, errs.IsIsNil},                                  // y nil
	}

	// All the tests!
	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := pk.MulPlaintext(&paillier.CipherText{C: theTest.y}, theTest.x)
			if theTest.expectedPass {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Tests for paillier multiplication with known answers
func TestMul(t *testing.T) {
	z25, err := paillier.NewPublicKey(nat("5"))
	require.NoError(t, err)
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	// newPk, err := paillier.NewPublicKey(parseNat("66563913295148834609789506"))
	require.NoError(t, err)

	// Compute: ɑ ≡ -2N -1  (N²)
	minusTwo := new(saferith.Nat).ModNeg(new(saferith.Nat).SetUint64(2), saferith.ModulusFromNat(nn))
	alpha := new(saferith.Nat).ModMul(n, minusTwo, saferith.ModulusFromNat(nn))
	alpha = new(saferith.Nat).Add(alpha, one, -1)

	tests := []struct {
		pk *paillier.PublicKey
		// Note: these values are in reverse-order from the order passed in as args
		c, a, expected *saferith.Nat
	}{
		// Small number tests: Z_{25}
		{z25, nat("1"), nat("0"), nat("1")},
		{z25, nat("2"), nat("2"), nat("4")},
		{z25, nat("2"), nat("1"), nat("2")},
		{z25, nat("8"), nat("4"), nat("21")},
		{z25, nat("7"), nat("3"), nat("18")},
		{z25, nat("6"), nat("0"), nat("1")},
		{z25, nat("4"), nat("3"), nat("14")},
		{z25, nat("8"), nat("1"), nat("8")},
		{z25, nat("2"), nat("2"), nat("4")},

		// large number tests
		{pk, x, zero, one}, // x^0 = 1
		{pk, y, one, y},    // y^1 = 1
		// {pk, zero, nMinusOne, zero}, // 0^{N-1} = 0
		{pk, nMinusOne, two, alpha}, // (N-1)² = N² - 2N - 1 ≡ -2N -1 (N²)

		// INVALID TEST - expected bigger than PK
		// large number test: WorlframAlpha test case
		//{
		//	newPk,
		//	parseNat("11659564086467828628"),
		//	parseNat("57089538512338875950"),
		//	parseNat("1487259371808822575685230766372478858208831958946972"),
		//},
	}
	// All the tests!
	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			actual, err := theTest.pk.MulPlaintext(&paillier.CipherText{C: theTest.c}, theTest.a)
			require.NoError(t, err)
			require.NotZero(t, theTest.expected.Eq(actual.C))
		})
	}
}

// EncryptWithNonce() is provided a nonce and must be deterministic
func TestLittleEncryptDeterministic(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	rBig, err := crand.Int(crand.Reader, pk.N.Big())
	require.NoError(t, err)
	r := new(saferith.Nat).SetBig(rBig, n.AnnouncedLen())

	msgBig, _ := crand.Int(crand.Reader, pk.N.Big())
	msg := new(saferith.Nat).SetBig(msgBig, n.AnnouncedLen())

	// Encrypt the same msg/nonce multiple times
	a0, err := pk.EncryptWithNonce(msg, r)
	require.NoError(t, err)

	a1, err := pk.EncryptWithNonce(msg, r)
	require.NoError(t, err)

	a2, err := pk.EncryptWithNonce(msg, r)
	require.NoError(t, err)

	// ❄️ == bad; confirm results are identical
	require.Equal(t, a0, a1)
	require.Equal(t, a0, a2)
}

// Tests the restrictions on input values for paillier.Encrypt
func TestEncryptErrorConditions(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)

	tests := []struct {
		msg, r          *saferith.Nat
		expectedPass    bool
		expectedErrFunc func(error) bool
	}{
		// Good
		{zero, one, true, nil},      // 0 ≤ m,r < N
		{one, nMinusOne, true, nil}, // 0 ≤ m,r < N
		{nMinusOne, two, true, nil}, // 0 ≤ m,r < N

		// Bad
		{zero, zero, false, errs.IsIsZero}, // r cannot be 0
		{nil, one, false, errs.IsIsNil},    // m nil
		{one, nil, false, errs.IsIsNil},    // r nil
		{nil, nil, false, errs.IsIsNil},    // both nil
		{n, one, false, errs.IsArgument},   // m == N
		{one, n, false, errs.IsArgument},   // r == N
	}

	// All the tests!
	for _, test := range tests {
		_, err := pk.EncryptWithNonce(test.msg, test.r)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

// Tests that each invocation of Encrypt() produces a distinct output
func TestEncryptIsRandomized(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	msg := one

	// Encrypt the same msg multiple times
	a0, _, err := pk.Encrypt(msg, crand.Reader)
	require.NoError(t, err)

	a1, _, err := pk.Encrypt(msg, crand.Reader)
	require.NoError(t, err)

	a2, _, err := pk.Encrypt(msg, crand.Reader)
	require.NoError(t, err)

	// ❄️ ❄️ ❄️
	require.NotEqual(t, a0, a1)
	require.NotEqual(t, a0, a2)
}

// Encrypt should succeed over a range of arbitrary, valid messages
func TestEncryptSucceeds(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	iterations := 100
	for i := 0; i < iterations; i++ {
		msg, err := crand.Int(crand.Reader, pk.N.Big())
		require.NoError(t, err)
		c, r, err := pk.Encrypt(new(saferith.Nat).SetBig(msg, n.AnnouncedLen()), crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, c, r)
	}
}

// Tests the restrictions on input values for paillier.Decrypt
func TestDecryptErrorConditions(t *testing.T) {
	// A fake secret key, but good enough to test parameter validation
	sk := &paillier.SecretKey{
		PublicKey: paillier.PublicKey{
			N: n,
		},
		Phi: nPlusOne,
	}

	tests := []struct {
		c               *saferith.Nat
		expectedPass    bool
		expectedErrFunc func(error) bool
	}{
		// Good: c ∈ Z_N²
		// TODO: Fix when L() param restrictions settled
		//{core.Zero, true},
		//{core.One, true},
		//{N, true},
		//{NplusOne, true},
		//{hundoN, true},
		//{NNminusOne, true},

		// Bad
		{nn, false, errs.IsArgument},        // c = N²
		{nnPlusOne, false, errs.IsArgument}, // c > N²
		{nil, false, errs.IsIsNil},          // nil
	}

	// All the tests!
	for _, test := range tests {
		decryptor, err := paillier.NewDecryptor(sk)
		if err != nil && test.expectedErrFunc != nil {
			continue
		}
		_, err = decryptor.Decrypt(&paillier.CipherText{C: test.c})
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}

	// nil values in the SecretKey
	sk = &paillier.SecretKey{
		PublicKey: paillier.PublicKey{N: nat("100")},
		Phi:       nil,
	}
	_, err := paillier.NewDecryptor(sk)
	require.Error(t, err)
}

// Decrypt·Encrypt is the identity function
func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Pre-computed safe primes
	p := nat("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	q := nat("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623")
	n := nat("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641")
	nMinusOne := new(saferith.Nat).Sub(n, one, n.AnnouncedLen())
	// Artbitrary value < 2^1024
	x := nat("20317113632585528798845062224869200275863225217624919914930609441107430244099181911960782321973293974573717329695193847701610218076524443400374940131739854056496412361090757880543495337916419061120521895395069964501013582917510846097488944684808895337780780147474736309539340360589608026856645992290890400384")

	// Create sk, pk for testing
	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)

	// Valid msgs ∈ Z_N
	msgs := []*saferith.Nat{
		zero,
		one,
		nMinusOne,
		x,
	}

	// All the tests!
	for _, m := range msgs {
		// Encrypt,validate
		c, _, err := pk.Encrypt(m, crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, c)

		// Decrypt-validate
		decryptor, err := paillier.NewDecryptor(sk)
		require.NoError(t, err)
		actual, err := decryptor.Decrypt(c)
		require.NoError(t, err)
		require.NotZero(t, m.Eq(actual))
	}
}

func TestNewSecretKeyErrorConditions(t *testing.T) {
	testArgs := []lcmTest{
		{
			x: nil,
			y: one,
		},
		{
			x: one,
			y: nil,
		},
		{
			x: nil,
			y: nil,
		},
	}
	for i, arg := range testArgs {
		test := arg
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := paillier.NewSecretKey(test.x, test.y)
			require.True(t, errs.IsIsNil(err))
		})
	}
}

func Test_Precomputed(t *testing.T) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(t, secretKey)
	require.NoError(t, err)
	if b, _, _ := p.Cmp(q); b == 1 {
		p, q = q, p
	}

	pMinusOne := new(saferith.Nat).Sub(p, one, -1)
	qMinusOne := new(saferith.Nat).Sub(q, one, -1)
	pq := new(saferith.Nat).Mul(p, q, -1)
	phi := new(saferith.Nat).Mul(pMinusOne, qMinusOne, -1)
	nn := new(saferith.Nat).Mul(pq, pq, -1)

	// validate key
	require.True(t, pq.Eq(secretKey.N) == 1, "N is valid")
	require.True(t, pq.Eq(secretKey.PublicKey.N) == 1, "N is valid")
	require.True(t, pq.Eq(secretKey.PublicKey.GetNModulus().Nat()) == 1, "precomputed N is valid")
	require.True(t, nn.Eq(secretKey.PublicKey.GetNNModulus().Nat()) == 1, "precomputed NN is valid")
	require.True(t, phi.Eq(secretKey.Phi) == 1, "phi is valid")
	require.True(t, p.Eq(secretKey.GetP()) == 1, "precomputed P is valid")
	require.True(t, q.Eq(secretKey.GetQ()) == 1, "precomputed Q is valid")
	require.True(t, new(saferith.Nat).ModMul(phi, secretKey.GetMu(), saferith.ModulusFromNat(pq)).Eq(one) == 1, "precomputed mu is valid")

	// validate n-CRT
	require.True(t, p.Eq(secretKey.GetCrtNParams().GetM1().Nat()) == 1, "precomputed N-CRT-P is valid")
	require.True(t, pMinusOne.Eq(secretKey.GetCrtNParams().GetPhiM1().Nat()) == 1, "precomputed CRT-PhiP is valid")
	require.True(t, q.Eq(secretKey.GetCrtNParams().GetM2().Nat()) == 1, "precomputed N-CRT-Q is valid")
	require.True(t, qMinusOne.Eq(secretKey.GetCrtNParams().GetPhiM2().Nat()) == 1, "precomputed N-CRT-PhiQ is valid")
	require.True(t, new(saferith.Nat).ModMul(p, secretKey.GetCrtNParams().GetM1InvM2(), saferith.ModulusFromNat(q)).Eq(one) == 1, "precomputed N-CRT-PInvQ is valid")

	pp := new(saferith.Nat).Mul(p, p, -1)
	ppMinusP := new(saferith.Nat).Sub(pp, p, -1)
	qq := new(saferith.Nat).Mul(q, q, -1)
	qqMinusQ := new(saferith.Nat).Sub(qq, q, -1)

	// validate nn-CRT
	require.True(t, pp.Eq(secretKey.GetCrtNNParams().GetM1().Nat()) == 1, "precomputed NN-CRT-PP is valid")
	require.True(t, ppMinusP.Eq(secretKey.GetCrtNNParams().GetPhiM1().Nat()) == 1, "precomputed NN-CRT-PhiPP is valid")
	require.True(t, qq.Eq(secretKey.GetCrtNNParams().GetM2().Nat()) == 1, "precomputed NN-CRT-QQ is valid")
	require.True(t, qqMinusQ.Eq(secretKey.GetCrtNNParams().GetPhiM2().Nat()) == 1, "precomputed NN-PhiQQ is valid")
	require.True(t, new(saferith.Nat).ModMul(pp, secretKey.GetCrtNNParams().GetM1InvM2(), saferith.ModulusFromNat(qq)).Eq(one) == 1, "precomputed PPInvQQ is valid")
}

func Test_MulScalarCrt(t *testing.T) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(t, secretKey)
	require.NoError(t, err)

	decryptor, err := paillier.NewDecryptor(secretKey)
	require.NoError(t, err)

	for i := 0; i < 64; i++ {
		lhs := rand.Uint32()
		rhs := rand.Uint32()
		lhsCipherText, _, err := secretKey.PublicKey.Encrypt(new(saferith.Nat).SetUint64(uint64(lhs)), prng)
		require.NoError(t, err)
		lhsTimesRhsCipherTextCrt, err := secretKey.MulPlaintext(lhsCipherText, new(saferith.Nat).SetUint64(uint64(rhs)))
		require.NoError(t, err)

		decryptedCrt, err := decryptor.Decrypt(lhsTimesRhsCipherTextCrt)
		require.NoError(t, err)
		require.Equal(t, uint64(lhs)*uint64(rhs), decryptedCrt.Uint64())
	}
}

func Test_EncryptCrt(t *testing.T) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(t, secretKey)
	require.NoError(t, err)

	for i := 0; i < 64; i++ {
		plainTextBig, err := crand.Int(prng, secretKey.N.Big())
		require.NoError(t, err)

		plainText := new(saferith.Nat).SetBig(plainTextBig, secretKey.N.AnnouncedLen())
		messageEncrypted, nonce, err := secretKey.PublicKey.Encrypt(plainText, prng)
		require.NoError(t, err)

		messageEncryptedCrt, err := secretKey.EncryptWithNonce(plainText, nonce)
		require.NoError(t, err)

		require.True(t, messageEncrypted.C.Eq(messageEncryptedCrt.C) == 1)
	}
}

func Test_JsonSerialisationRoundTrip(t *testing.T) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(t, secretKey)
	require.NoError(t, err)

	serialisedPublicKey, err := json.Marshal(&secretKey.PublicKey)
	require.NoError(t, err)
	var deserialisedPublicKey paillier.PublicKey
	err = json.Unmarshal(serialisedPublicKey, &deserialisedPublicKey)
	require.NoError(t, err)

	serialisedSecretKey, err := json.Marshal(secretKey)
	require.NoError(t, err)
	var deserialisedSecretKey paillier.SecretKey
	err = json.Unmarshal(serialisedSecretKey, &deserialisedSecretKey)
	require.NoError(t, err)

	// check public key
	require.True(t, deserialisedPublicKey.N.Eq(secretKey.PublicKey.N) == 1)
	require.True(t, deserialisedPublicKey.GetNModulus().Nat().Eq(secretKey.PublicKey.GetNModulus().Nat()) == 1)
	require.True(t, deserialisedPublicKey.GetNNModulus().Nat().Eq(secretKey.PublicKey.GetNNModulus().Nat()) == 1)

	// check secret key
	require.True(t, deserialisedSecretKey.N.Eq(secretKey.N) == 1)
	require.True(t, deserialisedSecretKey.Phi.Eq(secretKey.Phi) == 1)
	require.True(t, deserialisedSecretKey.GetP().Eq(secretKey.GetP()) == 1)
	require.True(t, deserialisedSecretKey.GetQ().Eq(secretKey.GetQ()) == 1)
	require.True(t, deserialisedSecretKey.GetMu().Eq(secretKey.GetMu()) == 1)
	crtN := deserialisedSecretKey.GetCrtNParams()
	require.True(t, crtN.GetM1().Nat().Eq(secretKey.GetCrtNParams().GetM1().Nat()) == 1)
	require.True(t, crtN.GetM2().Nat().Eq(secretKey.GetCrtNParams().GetM2().Nat()) == 1)
	require.True(t, crtN.GetPhiM1().Nat().Eq(secretKey.GetCrtNParams().GetPhiM1().Nat()) == 1)
	require.True(t, crtN.GetPhiM2().Nat().Eq(secretKey.GetCrtNParams().GetPhiM2().Nat()) == 1)
	require.True(t, crtN.GetM1InvM2().Eq(secretKey.GetCrtNParams().GetM1InvM2()) == 1)
	crtNN := deserialisedSecretKey.GetCrtNNParams()
	require.True(t, crtNN.GetM1().Nat().Eq(secretKey.GetCrtNNParams().GetM1().Nat()) == 1)
	require.True(t, crtNN.GetM2().Nat().Eq(secretKey.GetCrtNNParams().GetM2().Nat()) == 1)
	require.True(t, crtNN.GetPhiM1().Nat().Eq(secretKey.GetCrtNNParams().GetPhiM1().Nat()) == 1)
	require.True(t, crtNN.GetPhiM2().Nat().Eq(secretKey.GetCrtNNParams().GetPhiM2().Nat()) == 1)
	require.True(t, crtNN.GetM1InvM2().Eq(secretKey.GetCrtNNParams().GetM1InvM2()) == 1)
}

func Benchmark_DecryptCrt(b *testing.B) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	if bigger, _, _ := p.Cmp(q); bigger == 1 {
		p, q = q, p
	}

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(b, secretKey)
	require.NoError(b, err)

	messageBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(b, err)
	message := new(saferith.Nat).SetBig(messageBig, secretKey.N.AnnouncedLen())
	messageEncrypted, _, err := secretKey.Encrypt(message, prng)
	require.NoError(b, err)

	decryptor, err := paillier.NewDecryptor(secretKey)
	require.NoError(b, err)

	b.ResetTimer()
	b.Run("Decrypt CRT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decrypted, err := decryptor.Decrypt(messageEncrypted)
			require.NoError(b, err)
			require.True(b, decrypted.Eq(message) == 1)
		}
	})
}

func Benchmark_MulPlainTextCrt(b *testing.B) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	if bigger, _, _ := p.Cmp(q); bigger == 1 {
		p, q = q, p
	}

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(b, secretKey)
	require.NoError(b, err)

	messageBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(b, err)
	message := new(saferith.Nat).SetBig(messageBig, secretKey.N.AnnouncedLen())
	messageEncrypted, _, err := secretKey.Encrypt(message, prng)
	require.NoError(b, err)

	b.ResetTimer()
	b.Run("MulPlainText", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			scalarBig, err := crand.Int(prng, secretKey.N.Big())
			require.NoError(b, err)
			scalar := new(saferith.Nat).SetBig(scalarBig, secretKey.N.AnnouncedLen())
			_, err = secretKey.PublicKey.MulPlaintext(messageEncrypted, scalar)
			require.NoError(b, err)
		}
	})
	b.Run("MulPlainText CRT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			scalarBig, err := crand.Int(prng, secretKey.N.Big())
			require.NoError(b, err)
			scalar := new(saferith.Nat).SetBig(scalarBig, secretKey.N.AnnouncedLen())
			_, err = secretKey.MulPlaintext(messageEncrypted, scalar)
			require.NoError(b, err)
		}
	})
}

func Benchmark_EncryptCrt(b *testing.B) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	p := new(saferith.Nat).SetBig(pBig, 256)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(b, err)
	q := new(saferith.Nat).SetBig(qBig, 256)

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NotNil(b, secretKey)
	require.NoError(b, err)

	b.ResetTimer()
	b.Run("Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			plainTextBig, err := crand.Int(prng, secretKey.N.Big())
			require.NoError(b, err)

			plainText := new(saferith.Nat).SetBig(plainTextBig, secretKey.N.AnnouncedLen())
			_, _, err = secretKey.PublicKey.Encrypt(plainText, prng)
			require.NoError(b, err)
		}
	})
	b.Run("Encrypt CRT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			plainTextBig, err := crand.Int(prng, secretKey.N.Big())
			require.NoError(b, err)

			plainText := new(saferith.Nat).SetBig(plainTextBig, secretKey.N.AnnouncedLen())
			_, _, err = secretKey.Encrypt(plainText, prng)
			require.NoError(b, err)
		}
	})
}

func nat(nat string) *saferith.Nat {
	bigInt, ok := new(big.Int).SetString(nat, 10)
	if !ok {
		panic("invalid number")
	}
	return new(saferith.Nat).SetBig(bigInt, bigInt.BitLen())
}

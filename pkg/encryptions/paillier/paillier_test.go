package paillier_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/primes"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/encryptions/paillier"
)

func parseNat(nat string) *saferith.Nat {
	bigInt, ok := new(big.Int).SetString(nat, 10)
	if !ok {
		panic("invalid number")
	}
	return new(saferith.Nat).SetBig(bigInt, bigInt.BitLen())
}

var (
	zero          = parseNat("0")
	one           = parseNat("1")
	two           = parseNat("2")
	hundred       = parseNat("100")
	x             = parseNat("7146643783615963513942641287213372249533955323510461217840179896547799100626220786140425637990097431")
	y             = parseNat("1747698065194620177681258504464368264357359841192790848951902311522815739310792522712583635858354245")
	n             = parseNat("85832751158419329546684678412285185885848111422509523329716452068504806021136687603399722116388773253")
	nMinusOne     = new(saferith.Nat).Sub(n, one, -1)
	nPlusOne      = new(saferith.Nat).Add(n, one, -1)
	nTimesHundred = new(saferith.Nat).Mul(n, hundred, -1)

	nn         = new(saferith.Nat).Mul(n, n, -1)
	nnMinusOne = new(saferith.Nat).Sub(nn, one, -1)
	nnPlusOne  = new(saferith.Nat).Add(nn, one, -1)
)

func Example_encryptDecrypt() {
	hexMessage := strings.ToUpper(hex.EncodeToString([]byte("Hello World!")))
	mappedMessage, err := new(saferith.Nat).SetHex(hexMessage)
	if err != nil {
		panic(err)
	}
	pub, sec, err := paillier.NewKeys(256)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	// Ignoring the random value that was generated internally by `Encrypt`.
	cipher, _, err := pub.Encrypt(mappedMessage)
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
	pub, sec, err := paillier.NewKeys(256)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := parseNat("123")
	msg2 := parseNat("456")
	fmt.Printf("Encrypting %s and %s separately.\n", msg1.Big().String(), msg2.Big().String())

	cipher1, _, err := pub.Encrypt(msg1)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}
	cipher2, _, err := pub.Encrypt(msg2)
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
	pub, sec, err := paillier.NewKeys(256)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := parseNat("10")
	msg2 := parseNat("5")
	fmt.Printf("Encrypting %s.\n", msg1.Big().String())

	cipher1, _, err := pub.Encrypt(msg1)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Printf("Multiplying plain %s with the encrypted %s.\n", msg2.Big().String(), msg1.Big().String())
	cipher3, err := pub.Mul(msg2, cipher1)
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
	x        *saferith.Nat
	y        *saferith.Nat
	err      error
	expected *saferith.Nat

	_ types.Incomparable
}

func safeCompare(x, y *saferith.Nat) bool {
	if x == nil && y != nil {
		return false
	}
	if x != nil && y == nil {
		return false
	}
	if x == nil && y == nil {
		return true
	}

	return x.Eq(y) != 0
}

func runTestLcm(t *testing.T, testArgs []lcmTest) {
	t.Helper()
	for i, arg := range testArgs {
		testArg := arg
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			a, err := paillier.Lcm(testArg.x, testArg.y)
			if err != nil && testArg.err == nil {
				t.Errorf("lcm failed: %v", err)
			}
			if !safeCompare(a, testArg.expected) {
				t.Errorf("lcm failed. Expected %v, found: %v", testArg.expected, a)
			}
		})
	}
}

func TestLcm(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        parseNat("4"),
			y:        parseNat("6"),
			err:      nil,
			expected: parseNat("12"),
		},
		{
			x:        parseNat("10"),
			y:        parseNat("22"),
			err:      nil,
			expected: parseNat("110"),
		},
		{
			x:        parseNat("1"),
			y:        parseNat("3"),
			err:      nil,
			expected: parseNat("3"),
		},
		{
			x:        parseNat("5"),
			y:        parseNat("7"),
			err:      nil,
			expected: parseNat("35"),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmCommutative(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        parseNat("11"),
			y:        parseNat("7"),
			err:      nil,
			expected: parseNat("77"),
		},
		{
			x:        parseNat("7"),
			y:        parseNat("11"),
			err:      nil,
			expected: parseNat("77"),
		},
		{
			x:        parseNat("13"),
			y:        parseNat("23"),
			err:      nil,
			expected: parseNat("299"),
		},
		{
			x:        parseNat("23"),
			y:        parseNat("13"),
			err:      nil,
			expected: parseNat("299"),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmNil(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        nil,
			y:        parseNat("1"),
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
		{
			x:        parseNat("1"),
			y:        nil,
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
		{
			x:        nil,
			y:        nil,
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmZero(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        parseNat("0"),
			y:        parseNat("1"),
			err:      nil,
			expected: parseNat("0"),
		},
		{
			x:        parseNat("0"),
			y:        parseNat("0"),
			err:      nil,
			expected: parseNat("0"),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmBigPrimes(t *testing.T) {
	// Generated by OpenSSL
	x := parseNat("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	y := parseNat("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623")
	expected := parseNat("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641")

	x2 := parseNat("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	x3 := parseNat("199624032515728289045241179631920514454939035695180729995055822158745789192452713406851424173447485774951354235728394322982696160719973464933778580097775959312681723073700577658531340015313241640799019163953248377211698591166024389845418771351325354733438115315318038016037617205770677410860231617155107859183")
	y3 := parseNat("142249905617339142091532152811520246816977809135348639617427185924289265672711180486386239769195440660717504105473521478033326628103915862155595134226885191558983128407247227273401068113332266238311624168954823649558019882800072911119616964386221647824743035538953625688976296691147616508925455607033114354959")

	expected2 := parseNat("28396499784314989096609919418127345447157066075586506422680304338142086939236798450800279134642308338458035596559017626154823247809313781525454242216477721507296693149109832139024597927259443182893280359146077724553052468871051438675286719817790943900280362711254811533504902741179161752948522341835287769530110541739921633871308290020066875307078092554117637608375242902999872137629980200197702760214658136789637368191031173973090138816890631056194895911511193868568337270184231814553242352572122713100022187023932306383784997785740075483768764231396924369937421906728046753885386778340930941242102624489916449738497")
	testArgs := []lcmTest{
		{
			x: x, y: y, err: nil, expected: expected,
		},
		{
			x:        x2,
			y:        parseNat("1"),
			err:      nil,
			expected: x2,
		},
		{
			x:        x3,
			y:        y3,
			err:      nil,
			expected: expected2,
		},
	}
	runTestLcm(t, testArgs)
}

func TestLKnownCases(t *testing.T) {
	// test multiples of 5 for L
	pk, err := paillier.NewPublicKey(parseNat("5"))
	require.NoError(t, err)
	tests := []struct {
		in, expected *saferith.Nat
	}{
		{parseNat("6"), parseNat("1")},
		{parseNat("11"), parseNat("2")},
		{parseNat("16"), parseNat("3")},
		{parseNat("21"), parseNat("4")},
	}

	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			r, err := pk.L(theTest.in)
			require.NoError(t, err)
			require.NotZero(t, r.Eq(theTest.expected))
		})
	}
}

func TestLFailureCases(t *testing.T) {
	pk, err := paillier.NewPublicKey(parseNat("5"))
	require.NoError(t, err)
	tests := []*saferith.Nat{
		pk.N.Nat(),     // u = N should fail
		parseNat("25"), // u = NN should fail
		parseNat("51"), // u > NN should fail
		parseNat("9"),  // u ≢ 1 (mod 5) should fail
		parseNat("12"), // u ≢ 1 (mod 5) should fail
		parseNat("22"), // u ≢ 1 (mod 5) should fail
	}

	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := pk.L(theTest)
			require.True(t, errs.IsFailed(err))
		})
	}

	_, err = pk.L(nil)
	require.True(t, errs.IsIsNil(err))
}

type keygenTest struct {
	bits                        uint
	p, q, n, lambda, totient, u *saferith.Nat

	_ types.Incomparable
}

func TestKeyGen(t *testing.T) {
	testValues := []*keygenTest{
		// Small values
		// INVALID TEST - p has more than 32 bits!
		//{
		//	bits:    32,
		//	p:       parseNat("4294967387"),
		//	q:       parseNat("8589936203"),
		//	n:       parseNat("7700876508329"),
		//	lambda:  parseNat("18446747917705353986"),
		//	totient: parseNat("36893495835410707972"),
		//	u:       parseNat("30227647593197281524"),
		//},
		{
			bits:    32,
			p:       parseNat("2404778303"),
			q:       parseNat("2907092159"),
			n:       parseNat("6990912148784626177"),
			lambda:  parseNat("3495456071736377858"),
			totient: parseNat("6990912143472755716"),
			u:       parseNat("3614931622846492468"),
		},
		// Moderate values
		{
			bits:    128,
			p:       parseNat("505119856506205319276795183398241487263"),
			q:       parseNat("205972782400928578615836152187141707579"),
			n:       parseNat("104040942290540895974307747626520134740467527950099359068592315888198399066277"),
			lambda:  parseNat("52020471145270447987153873813260067369878217655596112585349842276306507935718"),
			totient: parseNat("104040942290540895974307747626520134739756435311192225170699684552613015871436"),
			u:       parseNat("95814396947082822381619843641016289162443592153179788942685091512428172029465"),
		},
		{
			bits:    128,
			p:       parseNat("335833617445150372903755348587631934583"),
			q:       parseNat("275426149345634030797050866270209482803"),
			n:       parseNat("92497360073732512809517386349687056338889420300408887876944500444198759476149"),
			lambda:  parseNat("46248680036866256404758693174843528169139080266809051736621847114670459029382"),
			totient: parseNat("92497360073732512809517386349687056338278160533618103473243694229340918058764"),
			u:       parseNat("37541288371367874015853812738289992945377756025517882548300075720005348319216"),
		},
		{
			bits:    256,
			p:       parseNat("115645895734860215235155088728394909334688633450524492586690742412129345961183"),
			q:       parseNat("94298418052417649431120534110853375174108454456092458684756344618179781451887"),
			n:       parseNat("10905225022052151768592443014939079805820716955892154646109970627753805040740378163517568530133182652794506558827042053659527293884287341299235199284102321"),
			totient: parseNat("10905225022052151768592443014939079805820716955892154646109970627753805040740168219203781252268516377171667310542533256571620676933015894212204890156689252"),
			lambda:  parseNat("5452612511026075884296221507469539902910358477946077323054985313876902520370084109601890626134258188585833655271266628285810338466507947106102445078344626"),
			u:       parseNat("169122108559803116345465577435019987080055058605295565203286696962456365170552011215103788832323625338104327792007096903690940420144823974727816140829004"),
		},
		{
			bits:    384,
			p:       parseNat("36006692832910486705531921197379033634897461505036495703751117530881437756504623602114452424392242359949564580091963"),
			q:       parseNat("36321876854655342367765793082986061200135195654801162378979445503936881469720608843798409137541849432902150243071007"),
			n:       parseNat("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253561264090635848856642357599288411446282200143037556882504679979558002244844355483553171478292766242112114935599016741"),
			totient: parseNat("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253488935520948283027569059885008046351447167485877719224421949416523183925618130251107258616730832150319263220775853772"),
			lambda:  parseNat("653915331510187903930034886233302721935942911306469970479401180999675646464892200886156143616105018235632886179126744467760474141513784529942504023175723583742938859612210974708261591962809065125553629308365416075159631610387926886"),
			u:       parseNat("715317338270237792745674161133027331913306953524485480270742409164181533024685207574377116318911340995248759257081568534206599002649096879000033274962046481163095418392051555090184840289513260640923181142724977346034839256290483076"),
		},
		// Large values
		{
			bits:    512,
			p:       parseNat("13334877681824046536664719753000692481615243060546695171749157112026072862294410162436291925578885141357927002155461724765584886877402066038258074266638227"),
			q:       parseNat("12122745362522189816168535264551355768089283231069686330301128627041958196835868405970767150401427191976786435200511843851744213149595052566013030642866907"),
			n:       parseNat("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858500001631307112890860155944955185080369964944108396477646372269079498823545159135772467319334869864305928043113234061678778620562861360302446649667820279453889"),
			totient: parseNat("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858499976173684068544623803111700167528321715239582104861264870218793759755514100005493898912275793883993594708399796705705210003233761333305328045396715369948756"),
			lambda:  parseNat("80827663288566554588862998438970751518522133571546591995386437860990148689988785450238937046890448682044255793069921722570996147501439201874375025929249988086842034272311901555850083764160857619791052430632435109396879877757050002746949456137896941996797354199898352852605001616880666652664022698357684974378"),
			u:       parseNat("143261270242335180420072816055839865064298362037063587448317467367577401621254503191376775173811231300545030557865973916661565869494495913728327166081853904903334058396967815592631415604767903602152339275761555997082956433277741333963496039496540726125762611561934388357363014028934069272035911913194424272603"),
		},
		{
			bits:    768,
			p:       parseNat("1346090925391135119143470623782502005582449208798686393499686094146720873293257316154858443761764176763426496081748327594475673914483978883075080616518148610864446133054517784818794038700373924492201179029136162262578223994386497407"),
			q:       parseNat("1267888740317619255987103204389173685200460862251480292534873171503916906509928280188817985770625788023592223617980306560361856737457586891910981446078699966027435065022526191471061668427090194699255004927681350300606724099539148139"),
			n:       parseNat("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565327188316266582808161080083810509077419565819105286361318424233748287133200189491965280880943430756926385486914657888021988499576975592342792662208243895780558951878131107691067112167457219510292850345325644694079605526537816712375573"),
			totient: parseNat("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565324574336600874053785949509982337401728782909034236194632389674482636495420386306368937204513898366961598468194958159387833662046323650777017676146181298931982059996933030647090822311750092046173658889141687876567042341589722786730028"),
			lambda:  parseNat("853346763873572355797144217207036737449198159572615785957429736537723384722221941213189103391574399080614492018296780283255708216497720338667995023705532142312572390190604190637899131292387787942781056087304346807291849813090782662287168300437026892974754991168700864391454517118097316194837241318247710193153184468602256949183480799234097479079693916831023161825388508838073090649465991029998466515323545411155875046023086829444570843938283521170794861393365014"),
			u:       parseNat("779879106968621551612916279464123438735012661607976871766884426257741506106933684516528094230394847057111517560275304735511075756729605155799199673159820709716869729022492405360829062001458468008371167876032343417620981083465124988041616116692784740773729428828021798152577117895496702246006365934433098458747623402795759758566365836593488130254049427800131843438461226605279227891251815575333006410913379796415963477224332006612563517643916428864744112156376520"),
		},
		{
			bits:    1024,
			p:       parseNat("323048346478810234804346724288317979049543453886657577003300101860710127877799870550562838407667268404599358826513829060160504303395418566677040422188661745067470888457815635033321184439746580337024906877384167362567610372271431186610013379997212856608697550064099211785613236213633622219571487990672693003787"),
			q:       parseNat("289955956844872723713267618282085026937397801221604643862282902289352466511076698253093993268863225914839327563609168378629851975959785812001060859728689670901677697805606458924299545852498153652948060776824445669854015488773545309215892532182626763404124068861635361632889336491051975303142403383113070034867"),
			n:       parseNat("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531738646998208894219436266840478325951526823776791414200683451217351791095609379048292074062880637329062218371522375097661526583290635879391529194601725476785472157424230313351359992497803391595095260449578824637692631790170131436072668730121222036510650215208397389118631464109460927478825133780143983053041329"),
			lambda:  parseNat("46834896205208695877949308479406106802186939437642912463715994059238867142884332605572634025122207347728070853815862451067915901623978425578029080826215699293332291462538578683057284457307956594503490220320333269460553435819558229523566620102443481296963611577440698388733076540917604315019523832060112406265562821347442605630459326248953961472769941260841575989908934106600864250610251239744208615602053417371389842566126050111368113505640337506425546659904062684751504418983445628701185883755573430552643740962308012330105082154543229788421412104521098445318696794735827272606480768378120940651209944385098645001338"),
			totient: parseNat("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531125642694885211260918652497907922945539882521683151979817868213201728501220502479488417231204106834742779685132252100222736227011280675012851093319808125369503008837966891257402371767511146861105287481924616024660210164309086459576842824209042196890637393589471654545212961536756241881302419888770197290002676"),
			u:       parseNat("38135949745652485811937226692116929429180649272477224483199257365577156885532690396567815884583937557608568699362433418166707048319324785327166624071125908609604488150973723257324029836008236113484260165701873141666619439620722921574373345283540196413007597899672199365492304562415424130214337263020773327553873482407654450455061737687873828877767689823341811598685374044652873284145859288532695538432223451947587392094598520855737584462011917578978549967062842845942828735580257392245879142299251014137170130879720213249399499545177941592508341271051010776972469394170182828098805388982944454017008931873419560331115"),
		},
	}

	for i, test := range testValues {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			idx := 0
			safePrimes := []*saferith.Nat{theTest.p, theTest.q}
			f := func(bits uint) (*saferith.Nat, error) {
				r := safePrimes[idx]
				idx = (idx + 1) % 2
				return r, nil
			}

			pub, sec, err := paillier.NewKeysWithSafePrimeGenerator(f, theTest.bits)
			require.NoError(t, err)
			require.True(t, pub.N.Nat().Eq(theTest.n) != 0)
			require.True(t, sec.Totient.Eq(theTest.totient) != 0)
			require.True(t, sec.Lambda.Eq(theTest.lambda) != 0)
			require.True(t, sec.U.Eq(theTest.u) != 0)
		})
	}
}

func TestKeyGeneratorErrorConditions(t *testing.T) {
	// Should fail if a safe prime cannot be generated.
	f := func(bits uint) (*saferith.Nat, error) {
		return nil, fmt.Errorf("safeprime error")
	}
	_, _, err := paillier.NewKeysWithSafePrimeGenerator(f, 1)
	require.Contains(t, err.Error(), "safeprime error")

	// Should fail if a gcd of p and q is zero.
	val := uint64(0)
	oneF := func(bits uint) (*saferith.Nat, error) {
		b := new(saferith.Nat).SetUint64(val)
		val += 1
		return b, nil
	}
	_, _, err = paillier.NewKeysWithSafePrimeGenerator(oneF, 1)
	require.True(t, errs.IsFailed(err))
}

func TestKeyGenSameInput(t *testing.T) {
	p := parseNat("4294967387")
	q := parseNat("8589936203")
	idx := 0
	safePrimes := []*saferith.Nat{p, q}
	f := func(bits uint) (*saferith.Nat, error) {
		r := safePrimes[idx]
		idx = (idx + 1) % 2
		return r, nil
	}
	pub1, sec1, err := paillier.NewKeysWithSafePrimeGenerator(f, 32)
	require.NoError(t, err)
	pub2, sec2, err := paillier.NewKeysWithSafePrimeGenerator(f, 32)
	require.NoError(t, err)
	require.True(t, pub1.N.Nat().Eq(pub2.N.Nat()) != 0)
	require.True(t, sec1.Lambda.Eq(sec2.Lambda) != 0)
	require.True(t, sec1.Totient.Eq(sec2.Totient) != 0)
	require.True(t, sec1.U.Eq(sec2.U) != 0)
}

func TestNewKeysDistinct(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping NewKeysDistinct")
	}
	pub1, sec1, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	pub2, sec2, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	// Ensure two fresh keys are distinct
	require.True(t, pub1.N.Nat().Eq(pub2.N.Nat()) == 0)
	require.True(t, sec1.Totient.Eq(sec2.Totient) == 0)
	require.True(t, sec1.Lambda.Eq(sec2.Lambda) == 0)
	require.True(t, sec1.U.Eq(sec2.U) == 0)
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
		{zero, one, true},
		{nMinusOne, parseNat("1024"), true}, // N-1, 1024
		{nPlusOne, nTimesHundred, true},     // N+1, 100N
		{one, nnMinusOne, true},             // one, N²-1

		{nil, one, false}, // x nil
		{one, nil, false}, // y nil

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

func TestSubPlain(t *testing.T) {
	pk, sk, err := paillier.NewKeys(128)
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
			encryptedX, _, err := pk.Encrypt(new(saferith.Nat).SetUint64(test.x))
			require.NoError(t, err)
			zEncrypted, err := pk.SubPlain(encryptedX, new(saferith.Nat).SetUint64(test.y))
			require.NoError(t, err)
			decryptor, err := paillier.NewDecryptor(sk)
			require.NoError(t, err)
			z, err := decryptor.Decrypt(zEncrypted)
			require.NoError(t, err)
			require.Equal(t, z.Uint64(), test.expected)
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
		{z9, parseNat("0"), parseNat("1"), parseNat("0")},
		{z9, parseNat("1"), parseNat("5"), parseNat("5")},
		{z9, parseNat("2"), parseNat("2"), parseNat("4")},
		{z9, parseNat("5"), parseNat("2"), parseNat("1")},
		{z9, parseNat("6"), parseNat("8"), parseNat("3")},
		{z9, parseNat("7"), parseNat("7"), parseNat("4")},
		{z9, parseNat("2"), parseNat("4"), parseNat("8")},
		{z9, parseNat("8"), parseNat("8"), parseNat("1")},
		{z9, parseNat("8"), parseNat("2"), parseNat("7")},

		// large number tests: Z_N²
		{pk, n, zero, zero},
		{pk, n, n, zero}, // N² ≡ 0 (N²)
		{pk, zero, nPlusOne, zero},
		{pk, nPlusOne, nPlusOne, z}, // (N+1)² = N² + 2N + 1 ≡ 2N + 1 (N²)
		{pk, parseNat("11659564086467828628"), parseNat("57089538512338875950"), parseNat("665639132951488346363609789106750696600")},
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
		{zero, one, true, nil},                   // 0 ≤ x,y < N
		{nMinusOne, parseNat("1024"), true, nil}, // 0 ≤ x,y < N
		{nMinusOne, nTimesHundred, true, nil},    // N-1 < N; 100N < N²
		{one, nnMinusOne, true, nil},             // 1 < N; N²-1 < N

		{nPlusOne, one, false, errs.IsInvalidArgument},                          // x > N; y ok
		{nPlusOne, nnPlusOne, false, errs.IsInvalidArgument},                    // both x,y bad
		{one, nnPlusOne, false, errs.IsInvalidArgument},                         // y bad
		{new(saferith.Nat).Add(nn, nn, -1), one, false, errs.IsInvalidArgument}, // x really bad
		{one, new(saferith.Nat).Add(nn, nn, -1), false, errs.IsInvalidArgument}, // y bad
		{n, one, false, errs.IsInvalidArgument},                                 // x boundary condition
		{one, nn, false, errs.IsInvalidArgument},                                // y boundary condition
		{nil, one, false, errs.IsIsNil},                                         // x nil
		{one, nil, false, errs.IsIsNil},                                         // y nil
	}

	// All the tests!
	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := pk.Mul(theTest.x, &paillier.CipherText{C: theTest.y})
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
	z25, err := paillier.NewPublicKey(parseNat("5"))
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
		{z25, parseNat("1"), parseNat("0"), parseNat("1")},
		{z25, parseNat("5"), parseNat("1"), parseNat("5")},
		{z25, parseNat("2"), parseNat("2"), parseNat("4")},
		{z25, parseNat("2"), parseNat("1"), parseNat("2")},
		{z25, parseNat("8"), parseNat("4"), parseNat("21")},
		{z25, parseNat("7"), parseNat("3"), parseNat("18")},
		{z25, parseNat("6"), parseNat("0"), parseNat("1")},
		{z25, parseNat("4"), parseNat("3"), parseNat("14")},
		{z25, parseNat("8"), parseNat("1"), parseNat("8")},
		{z25, parseNat("2"), parseNat("2"), parseNat("4")},

		// large number tests
		{pk, x, zero, one},          // x^0 = 1
		{pk, y, one, y},             // y^1 = 1
		{pk, zero, nMinusOne, zero}, // 0^{N-1} = 0
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
			actual, err := theTest.pk.Mul(theTest.a, &paillier.CipherText{C: theTest.c})
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
		{zero, zero, false, errs.IsIsZero},      // r cannot be 0
		{nil, one, false, errs.IsIsNil},         // m nil
		{one, nil, false, errs.IsIsNil},         // r nil
		{nil, nil, false, errs.IsIsNil},         // both nil
		{n, one, false, errs.IsInvalidArgument}, // m == N
		{one, n, false, errs.IsInvalidArgument}, // r == N
	}

	// All the tests!
	for _, test := range tests {
		_, err := pk.EncryptWithNonce(test.msg, test.r)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.True(t, test.expectedErrFunc(err))
		}
	}

	// Fail if N is nil
	pk = &paillier.PublicKey{N: nil, N2: nil}
	_, _, err = pk.Encrypt(one)
	require.True(t, errs.IsIsNil(err))
}

// Tests that each invocation of Encrypt() produces a distinct output
func TestEncryptIsRandomized(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	msg := one

	// Encrypt the same msg multiple times
	a0, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	a1, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	a2, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	// ❄️ ❄️ ❄️
	require.NotEqual(t, a0, a1)
	require.NotEqual(t, a0, a2)
}

// Small number tests of Encrypt()
func TestEncryptKnownAnswers(t *testing.T) {
	// N=3, NN=9
	z9, err := paillier.NewPublicKey(parseNat("3"))
	require.NoError(t, err)

	tests := []struct {
		m, r, expected *saferith.Nat // m,r inputs
	}{
		// All operations below mod 9
		{parseNat("1"), parseNat("1"), parseNat("4")}, // c = (3+1)^1 * (1^3) = 4*1 = 4
		{parseNat("0"), parseNat("1"), parseNat("1")}, // c = (3+1)^0 * 1^3 = 1
		{parseNat("2"), parseNat("2"), parseNat("2")}, // c = (3+1)^2 * 2^3 = 16*8 ≡ -7 ≡ 2
		{parseNat("1"), parseNat("2"), parseNat("5")}, // c = (3+1)^1 * 2^3 = 4*8 ≡ 5
	}

	// All the tests!
	for _, test := range tests {
		actual, err := z9.EncryptWithNonce(test.m, test.r)
		require.NoError(t, err)
		require.NotZero(t, test.expected.Eq(actual.C))
	}
}

// Encrypt should succeed over a range of arbitrary, valid messages
func TestEncryptSucceeds(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	iterations := 100
	for i := 0; i < iterations; i++ {
		msg, err := crand.Int(crand.Reader, pk.N.Big())
		require.NoError(t, err)
		c, r, err := pk.Encrypt(new(saferith.Nat).SetBig(msg, n.AnnouncedLen()))
		require.NoError(t, err)
		require.NotNil(t, c, r)
	}
}

// Tests the restrictions on input values for paillier.Decrypt
func TestDecryptErrorConditions(t *testing.T) {
	pk, err := paillier.NewPublicKey(n)
	require.NoError(t, err)
	// A fake secret key, but good enough to test parameter validation
	sk := &paillier.SecretKey{PublicKey: *pk, Lambda: nPlusOne, Totient: nPlusOne, U: nPlusOne}

	tests := []struct {
		c               *saferith.Nat
		expectedPass    bool
		expectedErrFunc func(error) bool
	}{
		// Good: c ∈ Z_N²
		// TODO: Fix when L() param restrictions settled
		// {core.Zero, true},
		// {core.One, true},
		// {N, true},
		// {NplusOne, true},
		// {hundoN, true},
		// {NNminusOne, true},

		// Bad
		{nn, false, errs.IsInvalidArgument},        // c = N²
		{nnPlusOne, false, errs.IsInvalidArgument}, // c > N²
		{nil, false, errs.IsIsNil},                 // nil
	}

	// All the tests!
	for _, test := range tests {
		decryptor, err := paillier.NewDecryptor(sk)
		require.NoError(t, err)
		_, err = decryptor.Decrypt(&paillier.CipherText{C: test.c})
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.True(t, test.expectedErrFunc(err))
		}
	}

	// nil values in the SecretKey
	sk = &paillier.SecretKey{
		PublicKey: paillier.PublicKey{N: saferith.ModulusFromNat(parseNat("100")), N2: saferith.ModulusFromNat(parseNat("10000"))},
		Lambda:    parseNat("200"),
		Totient:   nil,
		U:         nil,
	}
	decryptor, err := paillier.NewDecryptor(sk)
	require.NoError(t, err)
	_, err = decryptor.Decrypt(&paillier.CipherText{C: one})
	println(err.Error())
	require.True(t, errs.IsFailed(err))
}

// Decrypt·Encrypt is the identity function

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Pre-computed safe primes
	p := parseNat("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	q := parseNat("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623")
	n := parseNat("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641")
	nMinusOne := new(saferith.Nat).Sub(n, one, n.AnnouncedLen())
	// Artbitrary value < 2^1024
	x := parseNat("20317113632585528798845062224869200275863225217624919914930609441107430244099181911960782321973293974573717329695193847701610218076524443400374940131739854056496412361090757880543495337916419061120521895395069964501013582917510846097488944684808895337780780147474736309539340360589608026856645992290890400384")

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
		c, _, err := pk.Encrypt(m)
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

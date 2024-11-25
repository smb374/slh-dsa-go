package internal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/smb374/slh-dsa-go/params"
)

type KeyGenTestCase struct {
	SKSeed string `json:"skSeed"`
	SKPrf  string `json:"skPrf"`
	PKSeed string `json:"pkSeed"`
	SK     string `json:"sk"`
	PK     string `json:"pk"`
}

type SigGenTestCase struct {
	SK            string `json:"sk"`
	MessageLength int    `json:"messageLength"`
	Message       string `json:"message"`
	Signature     string `json:"signature"`
}

type SigVerTestCase struct {
	Passed        bool   `json:"testPassed"`
	SK            string `json:"sk"`
	PK            string `json:"pk"`
	AddRnd        string `json:"additionalRandomness"`
	MessageLength int    `json:"messageLength"`
	Message       string `json:"message"`
	Signature     string `json:"signature"`
	Reason        string `json:"reason"`
}

func TestKeyGen128F(t *testing.T) {
	var test_cases []KeyGenTestCase
	ctx := params.SLH_DSA_128_FAST()

	input, err := os.Open("./test_inputs/SHAKE128F_keygen.json")
	if err != nil {
		t.Fatalf("Failed to open test input: %v", err)
	}
	defer input.Close()

	val, err := io.ReadAll(input)
	err = json.Unmarshal(val, &test_cases)
	if err != nil {
		t.Fatalf("Failed to read test input: %v", err)
	}

	for i, tc := range test_cases {
		sk_seed, err := hex.DecodeString(tc.SKSeed)
		sk_prf, err := hex.DecodeString(tc.SKPrf)
		pk_seed, err := hex.DecodeString(tc.PKSeed)
		sk, err := hex.DecodeString(tc.SK)
		pk, err := hex.DecodeString(tc.PK)

		if err != nil {
			t.Fatalf("Failed on case %d: failed to decode input: %v", i, err)
		}

		skg, pkg := SLHKeyGenInternal(&ctx, sk_seed, sk_prf, pk_seed)

		if !bytes.Equal(sk, skg) {
			t.Fatalf("Failed on case %d: sk not matched", i)
		}

		if !bytes.Equal(pk, pkg) {
			t.Fatalf("Failed on case %d: pk not matched", i)
		}
	}
}

func TestSigGen128F(t *testing.T) {
	var test_cases []SigGenTestCase
	ctx := params.SLH_DSA_128_FAST()

	input, err := os.Open("./test_inputs/SHAKE128F_siggen.json")
	if err != nil {
		t.Fatalf("Failed to open test input: %v", err)
	}
	defer input.Close()

	val, err := io.ReadAll(input)
	err = json.Unmarshal(val, &test_cases)
	if err != nil {
		t.Fatalf("Failed to read test input: %v", err)
	}

	for i, tc := range test_cases {
		sk, err := hex.DecodeString(tc.SK)
		message, err := hex.DecodeString(tc.Message)
		signature, err := hex.DecodeString(tc.Signature)

		if err != nil {
			t.Fatalf("Failed on case %d: failed to decode input: %v", i, err)
		}

		sig := SLHSignInternal(&ctx, message, sk, nil)
		base := 0
		bound := ctx.Params.N

		t.Logf("Case %d: Test R randomness", i)
		if !bytes.Equal(sig[base:bound], signature[base:bound]) {
			t.Fatalf("Failed on case %d: randomness not matched", i)
		}

		base += bound
		bound += ctx.Params.K * (1 + ctx.Params.A) * ctx.Params.N
		sig_fors := sig[base:bound]
		signature_fors := signature[base:bound]
		t.Logf("Case %d: Test SIG_FORS", i)
		if !bytes.Equal(sig_fors, signature_fors) {
			t.Fatalf("Failed on case %d: FORS chunk not matched", i)
		}

		base += bound
		bound += (ctx.Params.H + ctx.Params.D*(2*ctx.Params.N+3)) * ctx.Params.N
		sig_ht := sig[base:bound]
		signature_ht := signature[base:bound]
		t.Logf("Case %d: Test SIG_HT", i)
		if !bytes.Equal(sig_ht, signature_ht) {
			t.Fatalf("Failed on case %d: FORS chunk not matched", i)
		}
	}
}

func TestSigVer128F(t *testing.T) {
	var test_cases []SigVerTestCase
	ctx := params.SLH_DSA_128_FAST()

	input, err := os.Open("./test_inputs/SHAKE128F_sigver.json")
	if err != nil {
		t.Fatalf("Failed to open test input: %v", err)
	}
	defer input.Close()

	val, err := io.ReadAll(input)
	err = json.Unmarshal(val, &test_cases)
	if err != nil {
		t.Fatalf("Failed to read test input: %v", err)
	}

	for i, tc := range test_cases {
		sk, err := hex.DecodeString(tc.SK)
		pk, err := hex.DecodeString(tc.PK)
		addrnd, err := hex.DecodeString(tc.AddRnd)
		msg, err := hex.DecodeString(tc.Message)
		sig, err := hex.DecodeString(tc.Signature)

		if err != nil {
			t.Fatalf("Failed to decode test case: %v", err)
		}

		_, sk_prf, _, _ := ctx.SkSplit(sk)

		Rgen := ctx.PRFmsg(sk_prf, addrnd, msg)

		// Not fatal on cases where R is modified and tc.Passed == false.
		if !bytes.Equal(Rgen, sig[:ctx.Params.N]) && tc.Passed {
			t.Fatalf("Failed on case %d: randomness unmatched.", i)
		}

		res := SLHVerifyInternal(&ctx, msg, sig, pk)

		if res != tc.Passed {
			t.Fatalf("Failed on case %d: verification result should be %v", i, tc.Passed)
		}
	}
}

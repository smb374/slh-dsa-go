package wots

import (
	"bytes"
	"crypto/rand"
	"testing"

	"codeberg.org/smb374/slh-dsa-go/address"
	"codeberg.org/smb374/slh-dsa-go/params"
)

func TestWots128f(t *testing.T) {
	ctx := params.SLH_DSA_128_FAST()
	adrs := address.Address{}
	sk_seed := make([]byte, ctx.Params.N)
	pk_seed := make([]byte, ctx.Params.N)
	msg := "AAAAAAAAAAAAAAAA"

	rand.Read(sk_seed)
	rand.Read(pk_seed)

	address.SetTypeAndClear(&adrs, address.WOTS_HASH)
	address.SetKeyPairAddress(&adrs, 1)

	pk_wots := WotsPKGen(&ctx, sk_seed, pk_seed, &adrs)
	sig := WotsSign(&ctx, []byte(msg), sk_seed, pk_seed, &adrs)
	pk_recover := WotsPKFromSig(&ctx, sig, []byte(msg), pk_seed, &adrs)

	if !bytes.Equal(pk_wots, pk_recover) {
		t.Fatalf("Test failed.")
	}
}

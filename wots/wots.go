package wots

import (
	"bytes"

	"github.com/smb374/slh-dsa-go/address"
	"github.com/smb374/slh-dsa-go/ctx"
	"github.com/smb374/slh-dsa-go/utils"
)

// NOTE: len = 2n + 3, w = 16

func Chain(ctx *ctx.Ctx, x []byte, i int, s int, pk_seed []byte, adrs *address.Address) []byte {
	tmp := x

	for j := i; j < i+s; j++ {
		address.SetHashAddress(adrs, j)
		tmp = ctx.F(pk_seed, adrs, tmp)
	}

	return tmp
}

func WotsPKGen(ctx *ctx.Ctx, sk_seed []byte, pk_seed []byte, adrs *address.Address) []byte {
	size := 2*ctx.Params.N + utils.LEN2
	var skAdrs address.Address
	var wotsPKadrs address.Address
	tmp := make([][]byte, size)

	copy(skAdrs[:], adrs[:])
	address.SetTypeAndClear(&skAdrs, address.WOTS_PRF)
	address.SetKeyPairAddress(&skAdrs, address.GetKeyPairAddress(adrs))
	// Generate 2n+3 public values
	for i := 0; i < size; i++ {
		address.SetChainAddress(&skAdrs, i)
		sk := ctx.PRF(pk_seed, sk_seed, &skAdrs)
		address.SetChainAddress(adrs, i)
		tmp[i] = Chain(ctx, sk, 0, utils.W-1, pk_seed, adrs)
	}

	copy(wotsPKadrs[:], adrs[:])
	address.SetTypeAndClear(&wotsPKadrs, address.WOTS_PK)
	address.SetKeyPairAddress(&wotsPKadrs, address.GetKeyPairAddress(adrs))

	pk := ctx.Tl(pk_seed, &wotsPKadrs, tmp)

	return pk
}

func WotsSign(ctx *ctx.Ctx, M []byte, sk_seed []byte, pk_seed []byte, adrs *address.Address) []byte {
	csum := 0
	len1 := 2 * ctx.Params.N
	size := len1 + utils.LEN2
	var skAdrs address.Address
	sig := make([][]byte, size)
	// Calculate checksum for message
	msg := utils.Base2b(M, utils.LGw, len1)
	for i := 0; i < len1; i++ {
		csum = csum + utils.W - 1 - int(msg[i])
	}
	csum = csum << ((8 - ((utils.LEN2 * utils.LGw) & 0x7)) & 0x7)
	msg = append(msg, utils.Base2b(utils.ToByte(csum, utils.DivCeil(utils.LEN2*utils.LGw, 8)), utils.LGw, utils.LEN2)...)

	copy(skAdrs[:], adrs[:])
	address.SetTypeAndClear(&skAdrs, address.WOTS_PRF)
	address.SetKeyPairAddress(&skAdrs, address.GetKeyPairAddress(adrs))
	// Calculate sk and signature, then store inside sig[i]
	for i := 0; i < size; i++ {
		address.SetChainAddress(&skAdrs, i)
		sk := ctx.PRF(pk_seed, sk_seed, &skAdrs)
		address.SetChainAddress(adrs, i)
		sig[i] = Chain(ctx, sk, 0, int(msg[i]), pk_seed, adrs)
	}

	return bytes.Join(sig, nil)
}

func WotsPKFromSig(ctx *ctx.Ctx, sig []byte, M []byte, pk_seed []byte, adrs *address.Address) []byte {
	csum := 0
	len1 := 2 * ctx.Params.N
	size := len1 + utils.LEN2
	tmp := make([][]byte, size)
	var wotsPKadrs address.Address
	// Calculate checksum for message
	msg := utils.Base2b(M, utils.LGw, len1)
	for i := 0; i < len1; i++ {
		csum = csum + utils.W - 1 - int(msg[i])
	}
	csum = csum << ((8 - ((utils.LEN2 * utils.LGw) & 0x7)) & 0x7)
	msg = append(msg, utils.Base2b(utils.ToByte(csum, utils.DivCeil(utils.LEN2*utils.LGw, 8)), utils.LGw, utils.LEN2)...)

	for i := 0; i < size; i++ {
		address.SetChainAddress(adrs, i)
		tmp[i] = Chain(ctx, sig[i*ctx.Params.N:(i+1)*ctx.Params.N], int(msg[i]), utils.W-1-int(msg[i]), pk_seed, adrs)
	}

	copy(wotsPKadrs[:], adrs[:])
	address.SetTypeAndClear(&wotsPKadrs, address.WOTS_PK)
	address.SetKeyPairAddress(&wotsPKadrs, address.GetKeyPairAddress(adrs))

	pk := ctx.Tl(pk_seed, &wotsPKadrs, tmp)

	return pk
}

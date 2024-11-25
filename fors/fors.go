package fors

import (
	"bytes"

	"codeberg.org/smb374/slh-dsa-go/address"
	"codeberg.org/smb374/slh-dsa-go/ctx"
	"codeberg.org/smb374/slh-dsa-go/utils"
)

func ForsSKGen(ctx *ctx.Ctx, sk_seed []byte, pk_seed []byte, adrs *address.Address, idx int) []byte {
	var skAdrs address.Address

	copy(skAdrs[:], adrs[:])
	address.SetTypeAndClear(&skAdrs, address.FORS_PRF)
	address.SetKeyPairAddress(&skAdrs, address.GetKeyPairAddress(adrs))
	address.SetTreeIndex(&skAdrs, idx)
	return ctx.PRF(pk_seed, sk_seed, &skAdrs)
}

func ForsNode(ctx *ctx.Ctx, sk_seed []byte, i int, z int, pk_seed []byte, adrs *address.Address) []byte {
	if z == 0 {
		// Leaf contains hashes of FORS secret values.
		sk := ForsSKGen(ctx, sk_seed, pk_seed, adrs, i)
		address.SetTreeHeight(adrs, 0)
		address.SetTreeIndex(adrs, i)
		return ctx.F(pk_seed, adrs, sk)
	} else {
		// Merkel Tree: node's value is hash(left || right)
		lnode := ForsNode(ctx, sk_seed, 2*i, z-1, pk_seed, adrs)
		rnode := ForsNode(ctx, sk_seed, 2*i+1, z-1, pk_seed, adrs)
		address.SetTreeHeight(adrs, z)
		address.SetTreeIndex(adrs, i)
		return ctx.H(pk_seed, adrs, [2][]byte{lnode, rnode})
	}
}

func ForsSign(ctx *ctx.Ctx, md []byte, sk_seed []byte, pk_seed []byte, adrs *address.Address) []byte {
	var sig_fors []byte
	indices := utils.Base2b(md, ctx.Params.A, ctx.Params.K)

	for i := 0; i < ctx.Params.K; i++ {
		auth := make([][]byte, ctx.Params.A)
		sig_fors = append(sig_fors, ForsSKGen(ctx, sk_seed, pk_seed, adrs, (i<<ctx.Params.A)+int(indices[i]))...)
		for j := 0; j < ctx.Params.A; j++ {
			s := int((indices[i] >> j) ^ 1)
			auth[j] = ForsNode(ctx, sk_seed, (i<<(ctx.Params.A-j))+s, j, pk_seed, adrs)
		}
		sig_fors = append(sig_fors, bytes.Join(auth, nil)...)
	}

	return sig_fors
}

func ForsPKFromSig(ctx *ctx.Ctx, sig_fors []byte, md []byte, pk_seed []byte, adrs *address.Address) []byte {
	var forsPkAdrs address.Address
	root := make([][]byte, ctx.Params.K)
	indices := utils.Base2b(md, ctx.Params.A, ctx.Params.K)

	for i := 0; i < ctx.Params.K; i++ {
		sk := sigForsGetSk(ctx, sig_fors, i)
		address.SetTreeHeight(adrs, 0)
		address.SetTreeIndex(adrs, (i<<ctx.Params.A)+int(indices[i]))
		node0 := ctx.F(pk_seed, adrs, sk)

		auth := sigForsGetAuth(ctx, sig_fors, i) // a*n bytes
		for j := 0; j < ctx.Params.A; j++ {
			var node1 []byte
			address.SetTreeHeight(adrs, j+1)
			cmp := (indices[i] >> uint(j)) & 1
			if cmp == 0 {
				address.SetTreeIndex(adrs, address.GetTreeIndex(adrs)>>1)
				node1 = ctx.H(pk_seed, adrs, [2][]byte{node0, authGet(ctx, auth, j)})
			} else {
				address.SetTreeIndex(adrs, (address.GetTreeIndex(adrs)-1)>>1)
				node1 = ctx.H(pk_seed, adrs, [2][]byte{authGet(ctx, auth, j), node0})
			}
			copy(node0, node1)
		}
		root[i] = node0
	}
	copy(forsPkAdrs[:], adrs[:])
	address.SetTypeAndClear(&forsPkAdrs, address.FORS_ROOTS)
	address.SetKeyPairAddress(&forsPkAdrs, address.GetKeyPairAddress(adrs))
	pk := ctx.Tl(pk_seed, &forsPkAdrs, root)

	return pk
}

func authGet(ctx *ctx.Ctx, auth []byte, i int) []byte {
	return auth[i*ctx.Params.N : (i+1)*ctx.Params.N]
}

func sigForsGetSk(ctx *ctx.Ctx, sig_fors []byte, i int) []byte {
	return sig_fors[i*(ctx.Params.A+1)*ctx.Params.N : (i*(ctx.Params.A+1)+1)*ctx.Params.N]
}

func sigForsGetAuth(ctx *ctx.Ctx, sig_fors []byte, i int) []byte {
	return sig_fors[(i*(ctx.Params.A+1)+1)*ctx.Params.N : (i+1)*(ctx.Params.A+1)*ctx.Params.N]
}

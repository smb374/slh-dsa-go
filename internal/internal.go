package internal

import (
	"codeberg.org/smb374/slh-dsa-go/address"
	"codeberg.org/smb374/slh-dsa-go/ctx"
	"codeberg.org/smb374/slh-dsa-go/fors"
	"codeberg.org/smb374/slh-dsa-go/utils"
	"codeberg.org/smb374/slh-dsa-go/xmss"
)

func SLHKeyGenInternal(ctx *ctx.Ctx, sk_seed []byte, sk_prf []byte, pk_seed []byte) (sk []byte, pk []byte) {
	var adrs address.Address

	copy(adrs[:], utils.ToByte(0, 32))
	address.SetLayerAddress(&adrs, ctx.Params.D-1)
	pk_root := xmss.XmssNode(ctx, sk_seed, 0, ctx.Params.HPrime, pk_seed, &adrs)

	sk = append(sk, sk_seed...)
	sk = append(sk, sk_prf...)
	sk = append(sk, pk_seed...)
	sk = append(sk, pk_root...)

	pk = append(pk, pk_seed...)
	pk = append(pk, pk_root...)

	return
}

// SLH SIG = randomness R || SIG_FORS || SIG_HT
func SLHSignInternal(ctx *ctx.Ctx, M []byte, sk []byte, addrnd []byte) []byte {
	var adrs address.Address
	sk_seed, sk_prf, pk_seed, pk_root := ctx.SkSplit(sk)
	KAdiv8 := utils.DivCeil(ctx.Params.K*ctx.Params.A, 8)                     // ceil(ka / 8)
	HsubHdivDdiv8 := utils.DivCeil(ctx.Params.H-ctx.Params.H/ctx.Params.D, 8) // ceil((h - h/d) / 8)
	Hdiv8D := utils.DivCeil(ctx.Params.H, 8*ctx.Params.D)                     // ceil(h / 8d)
	opt_rand := addrnd

	if opt_rand == nil {
		opt_rand = pk_seed
	}

	copy(adrs[:], utils.ToByte(0, 32))

	R := ctx.PRFmsg(sk_prf, opt_rand, M)

	sig := make([]byte, len(R))
	copy(sig, R)

	digest := ctx.Hmsg(R, pk_seed, pk_root, M)
	md := digest[0:KAdiv8]
	tmp_idx_tree := digest[KAdiv8 : KAdiv8+HsubHdivDdiv8]
	tmp_idx_leaf := digest[KAdiv8+HsubHdivDdiv8 : KAdiv8+HsubHdivDdiv8+Hdiv8D]
	idx_tree := utils.ToInt(tmp_idx_tree, HsubHdivDdiv8) & ((1 << (ctx.Params.H - ctx.Params.H/ctx.Params.D)) - 1)
	idx_leaf := utils.ToInt(tmp_idx_leaf, Hdiv8D) & ((1 << (ctx.Params.H / ctx.Params.D)) - 1)

	address.SetTreeAddress(&adrs, idx_tree)
	address.SetTypeAndClear(&adrs, address.FORS_TREE)
	address.SetKeyPairAddress(&adrs, idx_leaf)

	sig_fors := fors.ForsSign(ctx, md, sk_seed, pk_seed, &adrs)
	sig = append(sig, sig_fors...)

	pk_fors := fors.ForsPKFromSig(ctx, sig_fors, md, pk_seed, &adrs)
	sig_ht := xmss.HtSign(ctx, pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
	sig = append(sig, sig_ht...)

	return sig
}

func SLHVerifyInternal(ctx *ctx.Ctx, M []byte, sig []byte, pk []byte) bool {
	var adrs address.Address
	size := 2*ctx.Params.N + 3
	pk_seed, pk_root := ctx.PkSplit(pk)
	KAdiv8 := utils.DivCeil(ctx.Params.K*ctx.Params.A, 8)                     // ceil(ka / 8)
	HsubHdivDdiv8 := utils.DivCeil(ctx.Params.H-ctx.Params.H/ctx.Params.D, 8) // ceil((h - h/d) / 8)
	Hdiv8D := utils.DivCeil(ctx.Params.H, 8*ctx.Params.D)                     // ceil(h / 8d)

	if len(sig) != (1+ctx.Params.K*(1+ctx.Params.A)+ctx.Params.H+ctx.Params.D*size)*ctx.Params.N {
		return false
	}

	copy(adrs[:], utils.ToByte(0, 32))

	R := sig[:ctx.Params.N]
	sig_fors := sig[ctx.Params.N : (1+ctx.Params.K*(1+ctx.Params.A))*ctx.Params.N]
	sig_ht := sig[(1+ctx.Params.K*(1+ctx.Params.A))*ctx.Params.N:]

	digest := ctx.Hmsg(R, pk_seed, pk_root, M)
	md := digest[0:KAdiv8]
	tmp_idx_tree := digest[KAdiv8 : KAdiv8+HsubHdivDdiv8]
	tmp_idx_leaf := digest[KAdiv8+HsubHdivDdiv8 : KAdiv8+HsubHdivDdiv8+Hdiv8D]
	idx_tree := utils.ToInt(tmp_idx_tree, HsubHdivDdiv8) & ((1 << (ctx.Params.H - ctx.Params.H/ctx.Params.D)) - 1)
	idx_leaf := utils.ToInt(tmp_idx_leaf, Hdiv8D) & ((1 << (ctx.Params.H / ctx.Params.D)) - 1)

	address.SetTreeAddress(&adrs, idx_tree)
	address.SetTypeAndClear(&adrs, address.FORS_TREE)
	address.SetKeyPairAddress(&adrs, idx_leaf)

	pk_fors := fors.ForsPKFromSig(ctx, sig_fors, md, pk_seed, &adrs)
	return xmss.HtVerify(ctx, pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)
}

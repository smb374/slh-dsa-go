package xmss

import (
	"bytes"

	"codeberg.org/smb374/slh-dsa-go/address"
	"codeberg.org/smb374/slh-dsa-go/ctx"
	"codeberg.org/smb374/slh-dsa-go/utils"
	"codeberg.org/smb374/slh-dsa-go/wots"
)

func XmssNode(ctx *ctx.Ctx, sk_seed []byte, i int, z int, pk_seed []byte, adrs *address.Address) []byte {
	if z == 0 {
		// Leaf contains WOTS+ public key
		address.SetTypeAndClear(adrs, address.WOTS_HASH)
		address.SetKeyPairAddress(adrs, i)
		return wots.WotsPKGen(ctx, sk_seed, pk_seed, adrs)
	} else {
		// Merkel Tree: node's value is hash(left || right)
		lnode := XmssNode(ctx, sk_seed, 2*i, z-1, pk_seed, adrs)
		rnode := XmssNode(ctx, sk_seed, 2*i+1, z-1, pk_seed, adrs)
		address.SetTypeAndClear(adrs, address.TREE)
		address.SetTreeHeight(adrs, z)
		address.SetTreeIndex(adrs, i)
		return ctx.H(pk_seed, adrs, [2][]byte{lnode, rnode})
	}
}

func XmssSign(ctx *ctx.Ctx, M []byte, sk_seed []byte, idx int, pk_seed []byte, adrs *address.Address) []byte {
	auth := make([][]byte, ctx.Params.HPrime)
	var sig_xmss []byte
	// Calculate auth path nodes
	for j := 0; j < ctx.Params.HPrime; j++ {
		// k = floor(idx / 2^j) xor 1
		k := (idx >> j) ^ 1
		auth[j] = XmssNode(ctx, sk_seed, k, j, pk_seed, adrs)
	}

	address.SetTypeAndClear(adrs, address.WOTS_HASH)
	address.SetKeyPairAddress(adrs, idx)
	sig := wots.WotsSign(ctx, M, sk_seed, pk_seed, adrs)
	sig_xmss = append(sig_xmss, sig...)
	sig_xmss = append(sig_xmss, bytes.Join(auth, nil)...)
	return sig_xmss
}

func XmssPKFromSig(ctx *ctx.Ctx, idx int, sig_xmss_flat []byte, M []byte, pk_seed []byte, adrs *address.Address) []byte {
	size := 2*ctx.Params.N + 3
	sig := sig_xmss_flat[:size*ctx.Params.N]
	auth := sig_xmss_flat[size*ctx.Params.N : (size+ctx.Params.HPrime)*ctx.Params.N]
	var node1 []byte

	address.SetTypeAndClear(adrs, address.WOTS_HASH)
	address.SetKeyPairAddress(adrs, idx)
	node0 := wots.WotsPKFromSig(ctx, sig, M, pk_seed, adrs)

	address.SetTypeAndClear(adrs, address.TREE)
	address.SetTreeIndex(adrs, idx)
	// Climb auth path until root
	for k := 0; k < ctx.Params.HPrime; k++ {
		address.SetTreeHeight(adrs, k+1)
		cmp := (idx >> k) & 1
		if cmp == 0 { // floor(idx / 2^k) is even
			address.SetTreeIndex(adrs, address.GetTreeIndex(adrs)>>1)
			node1 = ctx.H(pk_seed, adrs, [2][]byte{node0, auth[k*ctx.Params.N : (k+1)*ctx.Params.N]})
		} else {
			address.SetTreeIndex(adrs, (address.GetTreeIndex(adrs)-1)>>1)
			node1 = ctx.H(pk_seed, adrs, [2][]byte{auth[k*ctx.Params.N : (k+1)*ctx.Params.N], node0})
		}
		copy(node0, node1)
	}

	return node0
}

func HtGetXMSSSig(ctx *ctx.Ctx, sig_ht []byte, idx int) []byte {
	size := 2*ctx.Params.N + utils.LEN2
	base := ctx.Params.HPrime + size
	return sig_ht[idx*base*ctx.Params.N : (idx+1)*base*ctx.Params.N]
}

func HtSign(ctx *ctx.Ctx, M []byte, sk_seed []byte, pk_seed []byte, tidx int, lidx int) []byte {
	var adrs address.Address

	copy(adrs[:], utils.ToByte(0, 32))
	address.SetTreeAddress(&adrs, tidx)
	sig_tmp := XmssSign(ctx, M, sk_seed, lidx, pk_seed, &adrs)
	sig_ht := sig_tmp

	root := XmssPKFromSig(ctx, lidx, sig_tmp, M, pk_seed, &adrs)
	for j := 1; j < ctx.Params.D; j++ {
		lidx = tidx & ((1 << ctx.Params.HPrime) - 1) // idx_leaf = h' LSBs of idx_tree
		tidx = tidx >> ctx.Params.HPrime             // remove h' LSBs of idx_tree
		address.SetLayerAddress(&adrs, j)
		address.SetTreeAddress(&adrs, tidx)
		sig_tmp = XmssSign(ctx, root, sk_seed, lidx, pk_seed, &adrs)
		sig_ht = append(sig_ht, sig_tmp...)
		if j < ctx.Params.D-1 {
			root = XmssPKFromSig(ctx, lidx, sig_tmp, root, pk_seed, &adrs)
		}
	}

	return sig_ht
}

func HtVerify(ctx *ctx.Ctx, M []byte, sig_ht []byte, pk_seed []byte, tidx int, lidx int, pk_root []byte) bool {
	var adrs address.Address

	copy(adrs[:], utils.ToByte(0, 32))
	address.SetTreeAddress(&adrs, tidx)
	sig_tmp := HtGetXMSSSig(ctx, sig_ht, 0)
	node := XmssPKFromSig(ctx, lidx, sig_tmp, M, pk_seed, &adrs)
	for j := 1; j < ctx.Params.D; j++ {
		lidx = tidx & ((1 << ctx.Params.HPrime) - 1) // idx_leaf = h' LSBs of idx_tree
		tidx = tidx >> ctx.Params.HPrime             // remove h' LSBs of idx_tree
		address.SetLayerAddress(&adrs, j)
		address.SetTreeAddress(&adrs, tidx)
		sig_tmp = HtGetXMSSSig(ctx, sig_ht, j)
		node = XmssPKFromSig(ctx, lidx, sig_tmp, node, pk_seed, &adrs)
	}
	return bytes.Equal(node, pk_root)
}

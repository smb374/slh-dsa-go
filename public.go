package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"codeberg.org/smb374/slh-dsa-go/ctx"
	"codeberg.org/smb374/slh-dsa-go/internal"
	"codeberg.org/smb374/slh-dsa-go/utils"
)

func SLHKeygen(ctx *ctx.Ctx) (sk []byte, pk []byte, err error) {
	sk_seed := make([]byte, ctx.Params.N)
	sk_prf := make([]byte, ctx.Params.N)
	pk_seed := make([]byte, ctx.Params.N)

	_, err = rand.Read(sk_seed)
	_, err = rand.Read(sk_prf)
	_, err = rand.Read(pk_seed)
	if err != nil {
		return
	}

	sk, pk = internal.SLHKeyGenInternal(ctx, sk_seed, sk_prf, pk_seed)
	return
}

func SLHSign(ctx *ctx.Ctx, M []byte, context []byte, sk []byte) (sig []byte, err error) {
	if len(context) > 255 {
		err = fmt.Errorf("Context string is too long.")
		return
	}

	addrnd := make([]byte, ctx.Params.N)
	_, err = rand.Read(addrnd)
	if err != nil {
		return
	}
	msg := bytes.Join([][]byte{
		utils.ToByte(0, 1),
		utils.ToByte(len(context), 1),
		context,
		M,
	}, nil)
	sig = internal.SLHSignInternal(ctx, msg, sk, addrnd)
	return
}

func SLHVerify(ctx *ctx.Ctx, M []byte, sig []byte, context []byte, pk []byte) bool {
	if len(context) > 255 {
		return false
	}
	msg := bytes.Join([][]byte{
		utils.ToByte(0, 1),
		utils.ToByte(len(context), 1),
		context,
		M,
	}, nil)
	return internal.SLHVerifyInternal(ctx, msg, sig, pk)
}

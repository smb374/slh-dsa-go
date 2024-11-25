package ctx

import (
	"bytes"
	"io"

	"codeberg.org/smb374/slh-dsa-go/address"
	"golang.org/x/crypto/sha3"
)

type SecurityCategory int

const (
	CATEGORY_1 SecurityCategory = 1
	CATEGORY_3 SecurityCategory = 3
	CATEGORY_5 SecurityCategory = 5
)

type ParameterSet struct {
	N        int
	H        int
	D        int
	HPrime   int
	A        int
	K        int
	M        int
	Category SecurityCategory
	PKBytes  int
	SigBytes int
}

type Ctx struct {
	Params ParameterSet
}

func (ctx *Ctx) Hmsg(r []byte, pk_seed []byte, pk_root []byte, M []byte) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.M)

	data = append(data, r...)
	data = append(data, pk_seed...)
	data = append(data, pk_root...)
	data = append(data, M...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

func (ctx *Ctx) PRF(pk_seed []byte, sk_seed []byte, adrs *address.Address) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.N)

	data = append(data, pk_seed...)
	data = append(data, adrs[:]...)
	data = append(data, sk_seed...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

func (ctx *Ctx) PRFmsg(sk_prf []byte, opt_rand []byte, M []byte) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.N)

	data = append(data, sk_prf...)
	data = append(data, opt_rand...)
	data = append(data, M...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

func (ctx *Ctx) F(pk_seed []byte, adrs *address.Address, m1 []byte) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.N)

	data = append(data, pk_seed...)
	data = append(data, adrs[:]...)
	data = append(data, m1...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

func (ctx *Ctx) H(pk_seed []byte, adrs *address.Address, m2 [2][]byte) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.N)

	data = append(data, pk_seed...)
	data = append(data, adrs[:]...)
	data = append(data, m2[0]...)
	data = append(data, m2[1]...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

func (ctx *Ctx) Tl(pk_seed []byte, adrs *address.Address, ml [][]byte) []byte {
	hash := sha3.NewShake256()

	data := make([]byte, 0)
	result := make([]byte, ctx.Params.N)

	data = append(data, pk_seed...)
	data = append(data, adrs[:]...)
	data = append(data, bytes.Join(ml, nil)...)

	hash.Write(data)
	io.ReadFull(hash, result)
	return result
}

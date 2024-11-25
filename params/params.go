package params

import "codeberg.org/smb374/slh-dsa-go/ctx"

func SLH_DSA_128_SMALL() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        16,
			H:        63,
			D:        7,
			HPrime:   9,
			A:        12,
			K:        14,
			M:        30,
			Category: ctx.CATEGORY_1,
			PKBytes:  32,
			SigBytes: 7856,
		},
	}
}

func SLH_DSA_128_FAST() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        16,
			H:        66,
			D:        22,
			HPrime:   3,
			A:        6,
			K:        33,
			M:        34,
			Category: ctx.CATEGORY_1,
			PKBytes:  32,
			SigBytes: 17088,
		},
	}
}

func SLH_DSA_192_SMALL() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        24,
			H:        63,
			D:        7,
			HPrime:   9,
			A:        14,
			K:        17,
			M:        39,
			Category: ctx.CATEGORY_3,
			PKBytes:  48,
			SigBytes: 16224,
		},
	}
}

func SLH_DSA_192_FAST() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        24,
			H:        66,
			D:        22,
			HPrime:   3,
			A:        8,
			K:        33,
			M:        42,
			Category: ctx.CATEGORY_3,
			PKBytes:  48,
			SigBytes: 35664,
		},
	}
}

func SLH_DSA_256_SMALL() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        32,
			H:        64,
			D:        8,
			HPrime:   8,
			A:        14,
			K:        22,
			M:        47,
			Category: ctx.CATEGORY_5,
			PKBytes:  64,
			SigBytes: 29792,
		},
	}
}

func SLH_DSA_256_FAST() ctx.Ctx {
	return ctx.Ctx{
		Params: ctx.ParameterSet{
			N:        32,
			H:        68,
			D:        17,
			HPrime:   4,
			A:        9,
			K:        35,
			M:        49,
			Category: ctx.CATEGORY_5,
			PKBytes:  64,
			SigBytes: 49856,
		},
	}
}

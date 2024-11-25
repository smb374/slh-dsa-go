package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/smb374/slh-dsa-go/ctx"
	"github.com/smb374/slh-dsa-go/internal"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate keys for SLH-DSA",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, err := Variant2Ctx(Variant)
		if err != nil {
			log.Fatal(err)
		}
		encoder := base64.StdEncoding

		sk, pk, err := SLHKeygen(&ctx)
		if err != nil {
			log.Fatal(err)
		}

		ske := encoder.EncodeToString(sk)
		pke := encoder.EncodeToString(pk)

		skf, err := os.OpenFile(fmt.Sprintf("%s/slh_dsa_key", Output), os.O_WRONLY|os.O_CREATE, 0600)
		pkf, err := os.OpenFile(fmt.Sprintf("%s/slh_dsa_key.pub", Output), os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer skf.Close()
		defer pkf.Close()

		_, err = skf.WriteString(ske)
		if err != nil {
			log.Fatalf("Failed to write secret key: %v", err)
		}
		_, err = pkf.WriteString(pke)
		if err != nil {
			log.Fatalf("Failed to write public key: %v", err)
		}
		log.Println("Key generation done.")
	},
}
var Output string

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&Output, "out", "o", ".", "Directory to output keys.")
}

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

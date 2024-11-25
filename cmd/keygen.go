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
		encoder := base64.StdEncoding
		ctx, err := Variant2Ctx(Variant)
		if err != nil {
			log.Fatal(err)
		}

		sk, pk, err := keygen(&ctx)
		if err != nil {
			log.Fatal(err)
		}

		ske := encoder.EncodeToString(sk)
		pke := encoder.EncodeToString(pk)

		skf, err := os.OpenFile(fmt.Sprintf("%s/slh_dsa_key", KeyOutputDir), os.O_WRONLY|os.O_CREATE, 0600)
		pkf, err := os.OpenFile(fmt.Sprintf("%s/slh_dsa_key.pub", KeyOutputDir), os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer skf.Close()
		defer pkf.Close()

		skf.Truncate(0)
		pkf.Truncate(0)

		_, err = skf.WriteString(ske)
		if err != nil {
			log.Fatalf("Failed to write secret key: %v", err)
		}
		_, err = pkf.WriteString(pke)
		if err != nil {
			log.Fatalf("Failed to write public key: %v", err)
		}
		fmt.Println("Key generation done.")
	},
}
var KeyOutputDir string

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&KeyOutputDir, "out", "o", ".", "Directory to output keys.")
}

func keygen(ctx *ctx.Ctx) (sk []byte, pk []byte, err error) {
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

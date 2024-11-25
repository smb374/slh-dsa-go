package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/smb374/slh-dsa-go/ctx"
	"github.com/smb374/slh-dsa-go/internal"
	"github.com/smb374/slh-dsa-go/utils"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify SLH-DSA message",
	Run: func(cmd *cobra.Command, args []string) {
		encoder := base64.StdEncoding

		ctx, err := Variant2Ctx(Variant)
		if err != nil {
			log.Fatal(err)
		}
		pk := make([]byte, ctx.Params.PKBytes)
		sig := make([]byte, ctx.Params.SigBytes)

		sigf, err := os.Open(SigInputPath)
		pkf, err := os.Open(PubKeyPath)
		if err != nil {
			log.Fatalf("Failed to open files: %v", err)
		}
		defer sigf.Close()
		defer pkf.Close()

		sige, err := io.ReadAll(sigf)
		pke, err := io.ReadAll(pkf)
		if err != nil {
			log.Fatalf("Failed to read files: %v", err)
		}

		_, err = encoder.Decode(sig, sige)
		_, err = encoder.Decode(pk, pke)
		if err != nil {
			log.Fatalf("Failed to decode contents: %v", err)
		}

		result := verify(&ctx, []byte(SignMessage), sig, []byte(Context), pk)
		fmt.Printf("Verification result: %v\n", result)
	},
}

var SigInputPath string
var PubKeyPath string

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(
		&PubKeyPath,
		"public-key",
		"p",
		"./slh_dsa_key.pub",
		"Public key to use. NOTE: The secret key you use should match your variant.",
	)
	verifyCmd.Flags().StringVarP(
		&SigInputPath,
		"signature",
		"s",
		"./slh_dsa_sig",
		"Signature of message.",
	)
	verifyCmd.Flags().StringVarP(
		&SignMessage,
		"message",
		"m",
		"",
		"Message to sign.")
	verifyCmd.Flags().StringVarP(
		&Context,
		"context",
		"c",
		"deadbeef",
		"Context string to use. Length should be < 255.")

	verifyCmd.MarkFlagRequired("message")
}

func verify(ctx *ctx.Ctx, M []byte, sig []byte, context []byte, pk []byte) bool {
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

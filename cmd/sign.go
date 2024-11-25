package cmd

import (
	"bytes"
	"crypto/rand"
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

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign message using SLH-DSA",
	Run: func(cmd *cobra.Command, args []string) {
		encoder := base64.StdEncoding

		ctx, err := Variant2Ctx(Variant)
		if err != nil {
			log.Fatal(err)
		}
		sk := make([]byte, 4*ctx.Params.N)

		skf, err := os.Open(SecretKeyPath)
		if err != nil {
			log.Fatalf("Failed to open secret key file: %v", err)
		}
		defer skf.Close()
		sigf, err := os.OpenFile(SigOutputPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open signature key file: %v", err)
		}
		defer sigf.Close()

		ske, err := io.ReadAll(skf)
		if err != nil {
			log.Fatalf("Failed to read secret key file: %v", err)
		}

		_, err = encoder.Decode(sk, ske)
		if err != nil {
			log.Fatalf("Failed to decode secret key: %v", err)
		}

		sig, err := sign(&ctx, []byte(SignMessage), []byte(SignContext), sk)
		if err != nil {
			log.Fatalf("Failed to sign message: %v", err)
		}

		sige := encoder.EncodeToString(sig)
		_, err = sigf.WriteString(sige)
		if err != nil {
			log.Fatalf("Failed to write signature: %v", err)
		}
		fmt.Println("Message signing done.")
	},
}
var SecretKeyPath string
var SignMessage string
var SignContext string
var SigOutputPath string

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(
		&SecretKeyPath,
		"secret-key",
		"s",
		"./slh_dsa_key",
		"Path of the secret key to use. NOTE: The secret key you use should match your variant.")
	signCmd.Flags().StringVarP(
		&SignMessage,
		"message",
		"m",
		"",
		"Message to sign.")
	signCmd.Flags().StringVarP(
		&SignContext,
		"context",
		"c",
		"deadbeef",
		"Context string to use. Length should be < 255.")
	signCmd.Flags().StringVarP(
		&SigOutputPath,
		"output",
		"o",
		"./slh_dsa_sig",
		"Signature output path.")

	signCmd.MarkFlagRequired("message")
}

func sign(ctx *ctx.Ctx, M []byte, context []byte, sk []byte) (sig []byte, err error) {
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

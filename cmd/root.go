/*
Copyright © 2024 Po-Yeh Chen <pchen1@wpi.edu>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/smb374/slh-dsa-go/ctx"
	"github.com/smb374/slh-dsa-go/params"
	"github.com/spf13/cobra"
)

var Variant string = "SHAKE-128f"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "slh-dsa-go",
	Short: "FIPS 205 SLH-DSA implementation in Go",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.slh-dsa-go.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().StringVarP(&Variant, "variant", "V", "SHAKE-128f", "Variant to use.")
}

func Variant2Ctx(variant string) (ctx ctx.Ctx, err error) {
	switch variant {
	case "SHAKE-128f":
		ctx = params.SLH_DSA_128_FAST()
	case "SHAKE-128s":
		ctx = params.SLH_DSA_128_SMALL()
	case "SHAKE-192f":
		ctx = params.SLH_DSA_192_FAST()
	case "SHAKE-192s":
		ctx = params.SLH_DSA_192_SMALL()
	case "SHAKE-256f":
		ctx = params.SLH_DSA_256_FAST()
	case "SHAKE-256s":
		ctx = params.SLH_DSA_256_SMALL()
	default:
		err = fmt.Errorf("Invalid variant [%s]", variant)
	}
	return
}

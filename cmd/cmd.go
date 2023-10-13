package cmd

import (
	"fmt"

	"os"

	"github.com/spf13/cobra"
)

const VERSION = "villus version 0.1 linux/amd64"

var rootCmd = &cobra.Command{
	Use:   "villus",
	Short: "go runtime simple monitor based on ebpf",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show version",
	Run:   versionCommandFunc,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCommandFunc(command *cobra.Command, args []string) {
	fmt.Println(VERSION)
}

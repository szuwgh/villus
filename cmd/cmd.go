package cmd

import (
	"fmt"

	"os"

	"github.com/spf13/cobra"
	"github.com/szuwgh/villus/user"
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

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "show version",
	Run:   startCommandFunc,
}

var rmcmd = &cobra.Command{
	Use:   "rm",
	Short: "show version",
	Run:   rmcmdFunc,
}

var listcmd = &cobra.Command{
	Use:   "list",
	Short: "show version",
	Run:   listcmdFunc,
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(listcmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(rmcmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listcmdFunc(command *cobra.Command, args []string) {
	fmt.Println("list filter")
	err := user.ListFilters("ens33")
	if err != nil {
		fmt.Println(err)
	}
}

func rmcmdFunc(command *cobra.Command, args []string) {
	fmt.Println("remove filter")
	err := user.RemoveTCFilters("ens33", user.DirectionToParent(user.DirEgress))
	if err != nil {
		fmt.Println(err)
	}
}

func startCommandFunc(command *cobra.Command, args []string) {
	fmt.Println("start")
	err := user.AttachEbpfTc("ens33")
	if err != nil {
		fmt.Println(err)
	}
	select {}
}

func versionCommandFunc(command *cobra.Command, args []string) {
	fmt.Println(VERSION)
	err := user.ObserveTC("ens33")
	if err != nil {
		fmt.Println(err)
	}
	select {}
}

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/szuwgh/villus/common/vlog"
	"github.com/szuwgh/villus/user"
)

var Interface string

// vls tc
// vls tc -i ens33 init
// vls tc -i ens33 ip ls
// vls tc -i ens33 ls
// vls tc -i ens33 class ls
// vls tc -i ens33 class rm -c 1.8.4.8
// vls tc -i ens33 ip rm -ip 1.8.4.8
// vls tc -i ens33 ip add -c xx -ip 1.8.4.8
// vls tc -i ens33 class add --qdisc 1048576 --index 3 --rate 300kb/s
var tcCmd = &cobra.Command{
	Use: "tc",
}

var tcInitCmd = &cobra.Command{
	Use: "init",
	Run: initCmdFunc,
}

var tcBPFCmd = &cobra.Command{
	Use: "bpf",
	Run: bpfCmdFunc,
}

/***********************************************************
 * del
 ***********************************************************/

var tcDelCmd = &cobra.Command{
	Use: "del",
	Run: bpfDelCmdFunc,
}

var tcDelClassCmd = &cobra.Command{
	Use: "class",
	Run: lsClassCmdFunc,
}

var tcDelIpCmd = &cobra.Command{
	Use:   "ip",
	Short: "",
	Run:   lsIpCmdFunc,
}

/***********************************************************
 * ls
 ***********************************************************/

var tcListCmd = &cobra.Command{
	Use: "ls",
	Run: lsCmdFunc,
}

var tcLsClassCmd = &cobra.Command{
	Use: "class",
	Run: lsClassCmdFunc,
}

var tcLsIpCmd = &cobra.Command{
	Use:   "ip",
	Short: "",
	Run:   lsIpCmdFunc,
}

/***********************************************************
 * add
 ***********************************************************/

var tcAddCmd = &cobra.Command{
	Use: "add",
}

var tcAddClassCmd = &cobra.Command{
	Use: "class",
	Run: addClassCmdFunc,
}

var tcAddIpCmd = &cobra.Command{
	Use:   "ip",
	Short: "",
	Run:   addIpCmdFunc,
}

// var tcDevmd = &cobra.Command{
// 	Use:   "dev",
// 	Short: "",
// 	Run:   startCommandFunc,
// }

func init() {
	tcCmd.PersistentFlags().StringVarP(&Interface, "interface", "i", "", "network interface such as eth0")
	tcCmd.MarkPersistentFlagRequired("interface")
	tcCmd.AddCommand(tcInitCmd)

	tcCmd.AddCommand(tcBPFCmd)
	tcBPFCmd.PersistentFlags().Uint32P("qdisc", "q", 0, "set qdisc handle")

	tcBPFCmd.AddCommand(tcDelCmd)

	tcCmd.AddCommand(tcListCmd)
	tcListCmd.AddCommand(tcLsClassCmd)
	tcLsClassCmd.Flags().Uint32P("qdisc", "q", 0, "set qdisc handle")

	tcListCmd.AddCommand(tcLsIpCmd)

	tcCmd.AddCommand(tcAddCmd)
	tcAddCmd.AddCommand(tcAddClassCmd)
	tcAddClassCmd.Flags().Uint16P("index", "", 1, "class handle")
	tcAddClassCmd.Flags().StringP("rate", "r", "100KB/s", "Set traffic rate")
	tcAddClassCmd.Flags().Uint32P("qdisc", "q", 0, "Set qdisc handle")
	tcAddClassCmd.MarkFlagRequired("qdisc")

	tcAddCmd.AddCommand(tcAddIpCmd)
	tcAddIpCmd.Flags().Uint32P("class", "c", 1, "class handle")
	tcAddIpCmd.Flags().StringP("daddr", "d", "", "destination ip address")
	tcAddIpCmd.MarkFlagRequired("class")
	tcAddIpCmd.MarkFlagRequired("daddr")

}

func initCmdFunc(command *cobra.Command, args []string) {
	err := user.InitTcQdisc(Interface)
	if err != nil {
		vlog.Println(err)
	}
}

func bpfCmdFunc(command *cobra.Command, args []string) {
	fmt.Println("attach ebpf")
	qdisc := getFlagUint32(command, "qdisc")
	err := user.AttachEbpfTc(Interface, qdisc)
	if err != nil {
		vlog.Println(err)
	}
	select {}
}

func bpfDelCmdFunc(command *cobra.Command, args []string) {
	fmt.Println("del ebpf")
	qdisc := getFlagUint32(command, "qdisc")
	err := user.DeleteEbpfTc(Interface, qdisc)
	if err != nil {
		vlog.Println(err)
	}
	//	select {}
}

func lsCmdFunc(command *cobra.Command, args []string) {
	err := user.LsTcQdisc(Interface)
	if err != nil {
		vlog.Println(err)
	}
}

func lsClassCmdFunc(command *cobra.Command, args []string) {
	qdisc := getFlagUint32(command, "qdisc")
	err := user.LsTcClass(Interface, qdisc)
	if err != nil {
		vlog.Fatalln(err)
	}
}

func addClassCmdFunc(command *cobra.Command, args []string) {
	rate := getFlagString(command, "rate")
	qdisc := getFlagUint32(command, "qdisc")
	index := getFlagUint16(command, "index")
	err := user.AddTcClass(user.TcClassConfig{IfName: Interface, Qdisc: qdisc, Rate: rate, Index: index})
	if err != nil {
		vlog.Fatalln(err)
	}
}

func addIpCmdFunc(command *cobra.Command, args []string) {
	fmt.Println("add ip")
	class := getFlagUint32(command, "class")
	daddr := getFlagString(command, "daddr")
	err := user.AddIp(daddr, class)

	if err != nil {
		vlog.Fatalln(err)
	} else {
		vlog.Println("success")
	}
	select {}
}

func lsIpCmdFunc(command *cobra.Command, args []string) {
	fmt.Println("ls ip")
	user.LsIp()
}

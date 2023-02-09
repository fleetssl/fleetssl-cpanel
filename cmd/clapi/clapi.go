package clapi

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"text/template"

	"golang.org/x/net/context"

	"google.golang.org/grpc"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"

	"gopkg.in/urfave/cli.v1"
)

var conn *grpc.ClientConn
var cl pb.PluginClient
var clCtx context.Context

func InitRpc(ctx *cli.Context) error {

	rpcConn, rpcContext, err := common.CreateRpcClient()
	if err != nil {
		return err
	}

	conn = rpcConn
	clCtx = rpcContext
	cl = pb.NewPluginClient(conn)

	return nil
}

func CloseRpc(ctx *cli.Context) error {
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func restartIfRequired(ctx *cli.Context) error {
	if ctx.GlobalBoolT("restart") == false {
		return nil
	}

	svcCmd, err := exec.LookPath("service")
	if err != nil {
		return err
	}

	cmd := exec.Command(svcCmd, "letsencrypt-cpanel", "restart")
	return cmd.Run()
}

func renderTemplate(fmt string, value interface{}) (string, error) {
	tpl, err := template.New("").Parse(fmt)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, value); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func hasTemplate(ctx *cli.Context) bool {
	return ctx.GlobalString("format") != ""
}

func printTemplate(ctx *cli.Context, v interface{}) error {
	buf, err := renderTemplate(ctx.GlobalString("format"), v)
	if err != nil {
		return err
	}

	fmt.Println(buf)
	return nil
}

type withError interface {
	GetErrors() []*pb.Error
}

func handleError(w withError) error {
	if w.GetErrors() == nil || len(w.GetErrors()) == 0 {
		return nil
	}

	all := []string{}
	for _, v := range w.GetErrors() {
		all = append(all, v.Error)
	}

	return fmt.Errorf("%s", strings.Join(all, ","))
}

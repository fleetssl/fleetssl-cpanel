package whmcgi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt-cpanel/cpanelgo"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"

	"golang.org/x/net/context"

	"regexp"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

var tasks sync.WaitGroup

// TODO: singleton for this package
func getRpc() (pb.PluginClient, context.Context, *grpc.ClientConn, error) {
	conn, ctx, err := common.CreateRpcClient()
	if err != nil {
		return nil, nil, nil, err
	}

	return pb.NewPluginClient(conn), ctx, conn, nil
}

func ServeWhmCgi(w http.ResponseWriter, r *http.Request) {
	// Increase the CPANELGO limit for the WHM CGI since we can hit
	// the cap depending how big the server is
	cpanelgo.ResponseSizeLimit = (100 * (1 * 1024 * 1024)) + 1337

	// dont close the cgi process until async stuff is done
	defer tasks.Wait()

	if r.Method == http.MethodPost && r.FormValue("api") != "" {
		serveApi(w, r)
		return
	}

	if !hasACL() {
		fmt.Fprint(w, "You do not have the required permissions to access this interface")
		return
	}

	whmcl, err := common.MakeWhmClient(true)
	if err != nil {
		fmt.Fprint(w, "Error connecting to WHM", err)
		return
	}

	allVhosts, err := whmcl.FetchSslVhosts()
	if err != nil {
		fmt.Fprintf(w, "Error fetching ssl vhosts: %v", err)
		return
	}

	cl, ctx, _, err := getRpc()
	if err != nil {
		fmt.Fprintf(w, "Error connecting to API: %v", err)
		return
	}

	ctx, _ = context.WithTimeout(ctx, 5*time.Second)

	resp, err := cl.ConfigGetEntries(ctx, &pb.ConfigGetEntriesRequest{})
	if err != nil {
		fmt.Fprintf(w, "Error loading config: %v", err)
		return
	}

	tpl, err := common.LoadTemplate("whm_home.html", nil)
	if err != nil {
		fmt.Fprintf(w, "Error loading template: %v", err)
		return
	}

	leVhosts := []whm.VhostEntry{}

	reg, err := regexp.Compile("Let.s Encrypt")
	if err != nil {
		fmt.Fprintf(w, "Error compiling regex: %v", err)
		return
	}

	for _, v := range allVhosts.Data.Vhosts {
		if reg.Match([]byte(v.Certificate.OrgName)) {
			leVhosts = append(leVhosts, v)
		}
	}

	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	if err := tpl.Execute(w, map[string]interface{}{
		"Vhosts":  leVhosts,
		"Configs": resp.Entries,
		"Params":  r.URL.Query(),
	}); err != nil {
		fmt.Fprint(w, fmt.Errorf("error executing template %q: %w", tpl.Name(), err))
		return
	}
}

type apiResult struct {
	Result interface{} `json:"result,omitempty"`
	Error  interface{} `json:"error,omitempty"`
}

func serveApi(w http.ResponseWriter, r *http.Request) {
	var out apiResult

	switch r.FormValue("api") {
	case "run_autossl_for_user_async":
		out = runAutoSSLForUser(r.PostFormValue("username"), true, r.PostFormValue("retry") == "true")
	case "run_autossl_for_user":
		out = runAutoSSLForUser(r.PostFormValue("false"), false, false)
	case "update_config":
		out = updateConfig(r.PostForm)
	}

	if out.Error != nil || out.Result != nil {
		buf, err := json.Marshal(out)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.WithError(err).Error("Error unmarshalling autossl api result")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(buf))
		return
	}

	if r.FormValue("redirect") != "" {
		http.Redirect(w, r, "letsencrypt.live.cgi?config=ok", http.StatusFound)
	} else {
		w.WriteHeader(http.StatusNoContent)

	}

	return
}

func updateConfig(vals url.Values) apiResult {
	cl, ctx, _, err := getRpc()
	if err != nil {
		return apiResult{
			Error: "Unable to talk to gRPC",
		}
	}

	ctx, _ = context.WithTimeout(ctx, 5*time.Second)

	req := &pb.ConfigUpdateEntriesRequest{
		Entries: []*pb.ConfigEntry{},
	}

	for key := range vals {
		if !strings.HasPrefix(key, "conf-") {
			continue
		}

		val := vals.Get(key)
		key = strings.TrimPrefix(key, "conf-")

		req.Entries = append(req.Entries, &pb.ConfigEntry{
			Key:   key,
			Value: val,
		})
	}
	resp, err := cl.ConfigUpdateEntries(ctx, req)
	if err != nil {
		log.WithError(err).Error("Failed to update config values")
		return apiResult{
			Error: err,
		}
	}

	if resp.Errors != nil || len(resp.Errors) > 0 {
		log.WithField("errors", resp.Errors).Error("Failed to update config values")
		return apiResult{
			Error: resp.Errors,
		}
	}

	return apiResult{}
}

func runAutoSSLForUser(username string, async, retry bool) apiResult {
	l := log.WithField("username", username).WithField("async", async)
	l.Info("Received run-auto-ssl request")

	if username == "" {
		return apiResult{
			Error: errors.New("No username provided"),
		}
	}

	cl, ctx, conn, err := getRpc()
	if err != nil {
		log.Println(err)
		return apiResult{
			Error: "Internal error :(",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)

	in := &pb.AutoSSLRunForUserRequest{
		User:  username,
		Retry: retry,
	}

	fn := func(username string, conn *grpc.ClientConn, ctx context.Context, cancel context.CancelFunc) (*pb.AutoSSLRunForUserResponse, error) {
		defer func() {
			conn.Close()
			tasks.Done()
		}()

		resp, err := cl.AutoSSLRunForUser(ctx, in)
		cancel()

		l.WithError(err).WithField("response", resp).Println("Autossl api response")
		return resp, err
	}

	// register in the tasks global so main goroutine doesnt end
	tasks.Add(1)

	// Fire and forget
	if async {
		go fn(in.User, conn, ctx, cancel)
		return apiResult{Result: "AutoSSL launched asynchronously"}
	}

	// otherwise do the work and wait
	resp, err := fn(in.User, conn, ctx, cancel)
	if err != nil {
		return apiResult{Error: err}
	}

	// TODO refactor out of here
	if len(resp.Errors) > 0 {
		var errs bytes.Buffer
		for _, v := range resp.Errors {
			errs.WriteString(v.Error + "\n")
		}

		return apiResult{Error: errs.String()}
	}

	return apiResult{Result: resp.Certificates}
}

func hasACL() bool {
	user := strings.ToLower(os.Getenv("REMOTE_USER"))
	if user == "root" {
		return true
	}

	f, err := os.Open("/var/cpanel/resellers")
	if err != nil {
		log.WithError(err).Error("Could not open resellers file while checking ACLs")
		return false
	}

	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.WithError(err).Error("Could not read line in resellers file while checking ACLs")
			break
		}

		split := strings.Split(line, ":")
		if len(split) != 2 {
			continue
		}
		if strings.ToLower(split[0]) != user {
			continue
		}

		acls := strings.Split(split[1], ",")
		for _, acl := range acls {
			if acl == "all" {
				return true
			}
		}
	}

	return false
}

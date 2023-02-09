package clapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/urfave/cli.v1"
)

var (
	apiMethodMap = map[string]string{
		"list-certificates":        http.MethodGet,
		"issue-certificate":        http.MethodPost,
		"remove-certificate":       http.MethodPost,
		"reinstall-certificate":    http.MethodPost,
		"reuse-certificate":        http.MethodPost,
		"remove-certificate-reuse": http.MethodPost,
	}
)

func API() cli.Command {
	return cli.Command{
		Name: "api",
		Usage: "Send requests to the plugin's JSON API " +
			"(https://cpanel.fleetssl.com/docs/for-developers/api/). " +
			"Outputs JSON.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "user",
				Usage: "The cPanel user to impersonate for the API request",
			},
			cli.StringFlag{
				Name:  "function",
				Usage: "The API function to invoke",
			},
			cli.IntFlag{
				Name:  "version",
				Usage: "The API version",
				Value: 1,
			},
			cli.BoolFlag{
				Name:  "insecure",
				Usage: "Whether to ignore HTTPS errors on the WHM/cPanel APIs",
			},
		},
		ArgsUsage: `{"the json request": "body"}`,
		Action:    sendAPIRequest,
	}
}

var errRemoteFailure = errors.New("sending the API request succeeded but the response indicated failure")

func sendAPIRequest(ctx *cli.Context) error {
	err := sendAPIRequestInner(ctx)

	if err != nil {
		// If it's a local error, we need to fake some JSON error output.
		// If it's a remote error, we've already printed it to stdout.
		if err != errRemoteFailure {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(map[string]any{
				"success": false,
				"errors":  []string{err.Error()},
				"data":    nil,
			})
		}
		// Regardless of where the error came from, exit with a status code
		os.Exit(1)
	}
	return nil
}

func sendAPIRequestInner(ctx *cli.Context) error {
	user := ctx.String("user")
	if user == "" {
		return errors.New("a `user` is required for JSON API requests")
	}

	function := ctx.String("function")
	functionMethod, ok := apiMethodMap[function]
	if function == "" || !ok {
		return errors.New("a valid `function` is required for JSON API requests")
	}

	if functionMethod == http.MethodPost && ctx.NArg() != 1 {
		return errors.New("exactly one argument (the JSON request body)" +
			"is expected for a POST request")
	} else if functionMethod != http.MethodPost && ctx.NArg() != 0 {
		return errors.New("exactly zero arguments are expected for non-POST requests")
	}

	var reqBody io.Reader
	if functionMethod == http.MethodPost {
		reqBody = strings.NewReader(ctx.Args().First())
	}

	apiClient, apiURL, err := getAuthenticatedAPIClient(user, ctx.BoolT("insecure"))
	if err != nil {
		return err
	}
	v := url.Values{}
	v.Set("api_version", strconv.Itoa(ctx.Int("version")))
	v.Set("api_function", function)
	apiURL = apiURL + "?" + v.Encode()

	req, err := http.NewRequest(functionMethod, apiURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", "fleetssl-cpanel/"+common.AppVersion)

	resp, err := apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("content-type")); mt != "application/json" {
		return fmt.Errorf("unexpected API response content type: %s", mt)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading API response: %w", err)
	}

	var decoded struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(buf, &decoded); err != nil {
		return fmt.Errorf("did not get a valid JSON response: %w", err)
	}

	fmt.Println(string(buf))

	if decoded.Success {
		return nil
	} else {
		return errRemoteFailure
	}
}

func getAuthenticatedAPIClient(user string, insecure bool) (*http.Client, string, error) {
	whmClient, err := common.MakeWhmClient(insecure)
	if err != nil {
		return nil, "", fmt.Errorf("failed to init WHM client: %w", err)
	}

	resp, err := whmClient.CreateUserSession(user, "cpaneld")
	if err == nil {
		err = resp.Error()
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to create cPanel user session: %w", err)
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, "",
			fmt.Errorf("failed to create cookiejar for cPanel HTTP client: %w", err)
	}
	var lastURL string
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			lastURL = req.URL.String()
			return nil
		},
		Jar: jar,
	}
	loginResp, err := httpClient.Get(resp.Data.Url)
	if err != nil || loginResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to login to cPanel user session: %d, %w",
			loginResp.StatusCode, err)
	}
	if lastURL == "" {
		return nil, "", errors.New("failed to get cPanel user session URL")
	}
	indexPos := strings.LastIndex(lastURL, "/index.html")
	if indexPos == -1 {
		return nil, "", errors.New("cPanel session URL was in the wrong format, aborting")
	}

	httpClient.CheckRedirect = nil
	return httpClient, lastURL[:indexPos] + "/letsencrypt/letsencrypt.live.cgi", nil
}

package cpanelcgi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

type apiResponse struct {
	Success bool        `json:"success"`
	Errors  []string    `json:"errors"`
	Data    interface{} `json:"data"`
}

type apiHandler struct {
	cpanelAPI cpanel.CpanelApi
}

func ServeCpanelCGIAPI(w http.ResponseWriter, r *http.Request) {
	cl, err := cpanel.NewLiveApi("unix", os.Getenv("CPANEL_CONNECT_SOCKET"))
	if err != nil {
		serveAPIError(w, http.StatusServiceUnavailable, fmt.Sprintf("cPanel API was unavailable: %s", err.Error()))
		return
	}
	defer cl.Close()

	// Users with the feature disabled shouldn't have access to the API either
	if featureEnabled, err := isFeatureEnabled(cl, ""); !featureEnabled {
		serveAPIError(w, http.StatusForbidden, "letsencrypt-cpanel feature is disabled on this account", err.Error())
		return
	}

	handler := apiHandler{cl}
	mux := http.NewServeMux()
	// Equivalent of list page
	mux.HandleFunc("/api/v1/list-certificates", handler.listCertificates)
	// Equivalent of action=issue
	mux.HandleFunc("/api/v1/issue-certificate", handler.issueCertificate)
	// Equivalent of action=remove
	mux.HandleFunc("/api/v1/remove-certificate", handler.removeCertificate)
	// Equivalent of action=reinstall
	mux.HandleFunc("/api/v1/reinstall-certificate", handler.reinstallCertificate)
	// Equivalent of action=reuse
	mux.HandleFunc("/api/v1/reuse-certificate", handler.reuseCertificate)
	// Equivalent of action=remove-reuse
	mux.HandleFunc("/api/v1/remove-certificate-reuse", handler.removeCertificateReuse)
	// Default 404 handler
	mux.HandleFunc("/", func(notFoundW http.ResponseWriter, _ *http.Request) {
		serveAPIError(notFoundW, http.StatusNotFound, "That API endpoint does not exist")
	})

	urlTranslationHandler := http.HandlerFunc(func(w1 http.ResponseWriter, r1 *http.Request) {
		// Translate from CGI-based API parameters to ones we expect in our servemux
		apiMethod := r1.FormValue("api_function")
		apiVers := r1.FormValue("api_version")
		if apiMethod == "" || apiVers == "" {
			serveAPIError(w, http.StatusBadRequest, "Could not figure out what the requested API URL was")
			return
		}
		r2 := new(http.Request)
		*r2 = *r1
		r2.URL = new(url.URL)
		*r2.URL = *r1.URL
		r2.URL.Path = fmt.Sprintf("/api/v%s/%s", apiVers, apiMethod)
		mux.ServeHTTP(w, r2)
	})

	urlTranslationHandler.ServeHTTP(w, r)
}

func processAPIRequestBody(w http.ResponseWriter, r *http.Request, dest interface{}) error {
	if r.Method != http.MethodPost {
		serveAPIError(w, http.StatusBadRequest, "API request method must be POST")
		return errors.New("API request method must be POST")
	}
	if r.Body == nil {
		serveAPIError(w, http.StatusBadRequest, "API request had no body")
		return errors.New("API request had no body")
	}
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(dest); err != nil {
		serveAPIError(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode the API request body: %s", err.Error()))
		return err
	}
	return nil
}

func serveAPIError(w http.ResponseWriter, status int, errors ...string) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(apiResponse{
		Success: false,
		Errors:  errors,
		Data:    nil,
	})
}

func serveAPISuccess(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(apiResponse{
		Success: true,
		Errors:  nil,
		Data:    data,
	})
}

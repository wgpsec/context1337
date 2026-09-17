package api

import (
	"net/http"
	"strings"

	"github.com/wgpsec/context1337/internal/auth"
)

func principalOf(r *http.Request) auth.Principal {
	return auth.FromContext(r.Context())
}

func requireRead(w http.ResponseWriter, r *http.Request) bool {
	if principalOf(r).AllowsRead() {
		return true
	}
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	return false
}

func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if principalOf(r).AllowsWrite() {
		return true
	}
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	return false
}

func requireCustomWrite(w http.ResponseWriter, r *http.Request) bool {
	if principalOf(r).AllowsCustomWrite() {
		return true
	}
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	return false
}

func requireRequestedSource(w http.ResponseWriter, r *http.Request, source string) bool {
	if source == "" || principalOf(r).AllowsSource(source) {
		return true
	}
	http.Error(w, `{"error":"forbidden source"}`, http.StatusForbidden)
	return false
}

func appendSourceAllowlist(where []string, args []interface{}, column string, principal auth.Principal) ([]string, []interface{}) {
	sources := principal.Sources
	if len(sources) == 0 {
		return where, args
	}
	placeholders := make([]string, len(sources))
	for i, source := range sources {
		placeholders[i] = "?"
		args = append(args, source)
	}
	where = append(where, column+" IN ("+strings.Join(placeholders, ",")+")")
	return where, args
}

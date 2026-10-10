package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// The caIssuers fetch: the network once, the cache after, a failure
// remembered for the run (an offline machine pays the timeout once), and
// nothing but http(s).
func TestFetchEKIssuerCachesAndRemembersFailures(t *testing.T) {
	defer func(d string) { ekIssuerCacheDir, ekFetchFailed = d, sync.Map{} }(ekIssuerCacheDir)
	ekIssuerCacheDir = t.TempDir()
	ekFetchFailed = sync.Map{}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/gone" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("certificate bytes"))
	}))
	defer srv.Close()

	for i := 0; i < 2; i++ {
		b, err := fetchEKIssuer(srv.URL + "/ca.cer")
		if err != nil || string(b) != "certificate bytes" {
			t.Fatalf("fetch %d: %q %v", i, b, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("the cache was not used: %d requests", hits.Load())
	}
	for i := 0; i < 2; i++ {
		if _, err := fetchEKIssuer(srv.URL + "/gone"); err == nil {
			t.Fatal("a 404 was taken")
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("a failed URL was asked again: %d requests", hits.Load())
	}
	if _, err := fetchEKIssuer("file:///etc/passwd"); err == nil {
		t.Fatal("a file URL was fetched")
	}
}

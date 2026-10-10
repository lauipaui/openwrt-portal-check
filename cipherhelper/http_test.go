package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeStrict204(t *testing.T) {
	for _, status := range []int{204, 200, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == 302 {
					w.Header().Set("Location", "/empty")
				}
				w.WriteHeader(status)
			}))
			defer srv.Close()
			e := probe204(srv.URL, time.Second)
			if (e == nil) != (status == 204) {
				t.Fatalf("status=%d error=%v", status, e)
			}
		})
	}
}
func TestTransportChunkedAndLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.Write([]byte("0123456789ABCDEF"))
	}))
	defer srv.Close()
	b, _, e := httpExchange("GET", srv.URL, nil, nil, time.Second, 32)
	if e != nil || string(b) != "0123456789ABCDEF" {
		t.Fatal(string(b), e)
	}
	if _, _, e = httpExchange("GET", srv.URL, nil, nil, time.Second, 8); e == nil {
		t.Fatal("oversize body accepted")
	}
}

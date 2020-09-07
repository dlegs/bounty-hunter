package subdomains

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestCrtsh(t *testing.T) {
	testCases := []struct {
		title     string
		domain    string
		certsc    chan []cert
		errc      chan error
		wantCerts []cert
		wantErr   bool
	}{
		{
			title:  "successfully fetch cert logs from crt.sh",
			domain: "legg.io",
			certsc: make(chan []cert),
			errc:   make(chan error),
			wantCerts: []cert{
				{
					IssuerCAID:     16418,
					IssuerName:     "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
					CommonName:     "dylan.legg.io",
					NameValue:      "dylan.legg.io",
					ID:             3305856898,
					EntryTimestamp: "2020-08-29T08:16:40.075",
					NotBefore:      "2020-08-29T07:16:39",
					NotAfter:       "2020-11-27T07:16:39",
				},
			},
			wantErr: false,
		},
		{
			title:   "upstream crtsh error caught",
			domain:  "invalid.io",
			certsc:  make(chan []cert),
			errc:    make(chan error),
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				switch req.URL.String() {
				case "/%3Fq=legg.io&output=json":
					rw.Write([]byte(`[{"issuer_ca_id":16418,"issuer_name":"C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3","common_name":"dylan.legg.io","name_value":"dylan.legg.io","id":3305856898,"entry_timestamp":"2020-08-29T08:16:40.075","not_before":"2020-08-29T07:16:39","not_after":"2020-11-27T07:16:39"}]`))
				case "/%3Fq=invalid.io&output=json":
					rw.Write([]byte("invalid json"))
				default:
					t.Fatalf("unknown URL %q", req.URL.String())
				}
			}))
			defer server.Close()
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{
				http:     server.Client(),
				crtshURL: u,
			}
			go c.crtsh(tc.domain, tc.certsc, tc.errc)
			gotErr := <-tc.errc
			switch {
			case gotErr == nil && tc.wantErr:
				t.Errorf("crtsh(%q) ran successfully, want err", tc.domain)
			case gotErr != nil && !tc.wantErr:
				t.Errorf("crtsh(%q) got err %v, want nil", tc.domain, gotErr)
			}
			if gotErr != nil {
				return
			}
			gotCerts := <-tc.certsc
			if !reflect.DeepEqual(gotCerts, tc.wantCerts) {
				t.Errorf("crtsh(%q) got certs %v, want %v", tc.domain, gotCerts, tc.wantCerts)
			}
		})
	}
}

func Test_dedupe(t *testing.T) {
	tests := []struct {
		title          string
		certs          []cert
		wantSubdomains []string
	}{
		{
			title: "successfully dedupe certs",
			certs: []cert{
				{
					NameValue: "dylan.legg.io\ndylan.legg.io",
				},
				{
					NameValue: "harrison.legg.io",
				},
				{
					NameValue: "harrison.legg.io",
				},
				{
					NameValue: "does-not-resolve-sdfsdfqwer.com",
				},
			},
			wantSubdomains: []string{
				"dylan.legg.io",
				"harrison.legg.io",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.title, func(t *testing.T) {
			if gotSubdomains := dedupe(tc.certs); !reflect.DeepEqual(gotSubdomains, tc.wantSubdomains) {
				t.Errorf("dedupe(%v) got %v, want %v", tc.certs, gotSubdomains, tc.wantSubdomains)
			}
		})
	}
}

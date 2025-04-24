package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		input http.Header
		want  string
		wantE error
	}

	headers := http.Header{}
	headers.Add("Authorization", "ApiKey SampleKey")

	noAuthHeaders := http.Header{}

	malformedAuthHeaders := http.Header{}
	malformedAuthHeaders.Add("Authorization", "SampleKey")

	tests := []test{
		{
			input: headers,
			want:  "SampleKey",
			wantE: nil,
		},
		{
			input: noAuthHeaders,
			want:  "",
			wantE: ErrNoAuthHeaderIncluded,
		},
		{
			input: malformedAuthHeaders,
			want:  "",
			wantE: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		got, gotE := GetAPIKey(tc.input)
		if gotE != tc.wantE {
			if gotE == nil || tc.wantE == nil {
				t.Fatalf("expected error: %v, got: %v", tc.wantE, gotE)
				continue
			}
			if gotE.Error() == tc.wantE.Error() {
				continue
			}
			t.Fatalf("expected error: %v, got: %v", tc.wantE, gotE)
		}
		if got != tc.want {
			t.Fatalf("expected: %v, got: %v", tc.want, got)
		}
	}
}

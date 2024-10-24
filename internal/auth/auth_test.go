package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey: "my-secret-api-key",
			expectedErr: nil,
		},
		{
			name: "Incorrect Authorization Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %v, got %v", tt.expectedKey, apiKey)
			}

			if err != nil && tt.expectedErr != nil {
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

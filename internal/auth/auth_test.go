package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		expectError string // compare by string instead of error value
	}{
		{
			name:        "no authorization header",
			headers:     http.Header{},
			wantKey:     "",
			expectError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:     "",
			expectError: "malformed authorization header",
		},
		{
			name: "malformed header - too short",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			expectError: "malformed authorization header",
		},
		{
			name: "valid ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey:     "abc123",
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.expectError != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectError)
				} else if err.Error() != tt.expectError {
					t.Errorf("expected error %q, got %q", tt.expectError, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}

package configaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

func makeTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + ".sig"
}

func TestProviderAuthenticateOAuthBearerTokens(t *testing.T) {
	p := newProvider("config-api-key", []string{"configured-secret"})

	codexToken := makeTestJWT(t, map[string]any{
		"iss": "https://auth.openai.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "efc577c5-a718-41db-8e93-0d7120aee5c2",
			"user_id":            "user-123",
		},
	})
	unrelatedJWT := makeTestJWT(t, map[string]any{
		"iss": "https://example.com",
		"sub": "user-123",
	})

	tests := []struct {
		name          string
		authorization string
		wantPrincipal string
		wantSource    string
		wantErrCode   sdkaccess.AuthErrorCode
	}{
		{
			name:          "configured api key",
			authorization: "Bearer configured-secret",
			wantPrincipal: "configured-secret",
			wantSource:    "authorization",
		},
		{
			name:          "claude oauth bearer token",
			authorization: "Bearer sk-ant-oat01-test-token",
			wantPrincipal: "claude-oauth",
			wantSource:    "claude-oauth",
		},
		{
			name:          "codex oauth bearer token",
			authorization: "Bearer " + codexToken,
			wantPrincipal: "codex-oauth",
			wantSource:    "codex-oauth",
		},
		{
			name:          "unrelated jwt rejected",
			authorization: "Bearer " + unrelatedJWT,
			wantErrCode:   sdkaccess.AuthErrorCodeInvalidCredential,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8317/v1/models", nil)
			req.Header.Set("Authorization", tc.authorization)

			res, authErr := p.Authenticate(context.Background(), req)
			if tc.wantErrCode != "" {
				if authErr == nil || authErr.Code != tc.wantErrCode {
					t.Fatalf("Authenticate() error = %#v, want code %s", authErr, tc.wantErrCode)
				}
				return
			}
			if authErr != nil {
				t.Fatalf("Authenticate() unexpected error: %v", authErr)
			}
			if res == nil || res.Principal != tc.wantPrincipal || res.Metadata["source"] != tc.wantSource {
				t.Fatalf("Authenticate() = %#v, want principal=%q source=%q", res, tc.wantPrincipal, tc.wantSource)
			}
		})
	}
}

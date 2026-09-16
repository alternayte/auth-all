package oauthprovider

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alternayte/auth-all/internal/jws"
)

// errNoProof reports a request that carries no DPoP header.
var errNoProof = errors.New("authall/oauthprovider: the request carries no DPoP proof")

// dpopClaims are the claims of a DPoP proof.
type dpopClaims struct {
	JTI            string `json:"jti"`
	HTTPMethod     string `json:"htm"`
	HTTPURI        string `json:"htu"`
	IssuedAt       int64  `json:"iat"`
	AccessTokenSum string `json:"ath"`
	Nonce          string `json:"nonce"`
}

// checkDPoP verifies the DPoP proof of a request and returns the thumbprint of
// the proof key. It returns errNoProof when the request carries no header.
//
// accessToken is the presented access token of a resource request, and it is
// empty at the token endpoint. RFC 9449 binds the proof to the token with the
// ath claim, so a stolen proof cannot travel with another token.
func (p *Plugin) checkDPoP(r *http.Request, accessToken string) (string, error) {
	header := r.Header.Values("DPoP")
	if len(header) == 0 {
		return "", errNoProof
	}
	if len(header) > 1 {
		return "", errors.New("the request carries more than one DPoP proof")
	}
	head, payload, err := jws.Parse(header[0])
	if err != nil {
		return "", errors.New("the DPoP proof is malformed")
	}
	if head.Type != "dpop+jwt" || head.JWK == nil {
		return "", errors.New("the DPoP proof carries no proof key")
	}
	if _, private := head.JWK["d"]; private {
		return "", errors.New("the DPoP proof key carries private material")
	}
	pub, err := jws.PublicKeyFromJWK(head.JWK)
	if err != nil {
		return "", errors.New("the DPoP proof key is unusable")
	}
	if _, err := jws.Verify(header[0], pub); err != nil {
		return "", errors.New("the DPoP proof signature is invalid")
	}
	var claims dpopClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("the DPoP proof is malformed")
	}
	if !strings.EqualFold(claims.HTTPMethod, r.Method) {
		return "", errors.New("the DPoP proof names another method")
	}
	if !p.sameRequestURI(claims.HTTPURI, r) {
		return "", errors.New("the DPoP proof names another URI")
	}
	age := p.now().Sub(time.Unix(claims.IssuedAt, 0))
	if age > DefaultDPoPProofWindow || age < -DefaultDPoPProofWindow {
		return "", errors.New("the DPoP proof is outside the accepted window")
	}
	if claims.JTI == "" {
		return "", errors.New("the DPoP proof carries no identifier")
	}
	// The identifier is single use inside the accepted window, so a captured
	// proof reaches no second request.
	if err := p.rows.ClaimOAuthProof(r.Context(), claims.JTI,
		p.now().Add(DefaultDPoPProofWindow)); err != nil {
		return "", errors.New("the DPoP proof is replayed")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims.AccessTokenSum != jws.Encode(sum[:]) {
			return "", errors.New("the DPoP proof names another access token")
		}
	}
	return jws.Thumbprint(head.JWK)
}

// sameRequestURI compares the htu claim with the request target. The
// comparison drops the query and the fragment, as RFC 9449 requires.
func (p *Plugin) sameRequestURI(htu string, r *http.Request) bool {
	if htu == "" {
		return false
	}
	if i := strings.IndexAny(htu, "?#"); i >= 0 {
		htu = htu[:i]
	}
	// The mounted handler can see the path with or without the base path, so
	// the comparison accepts the absolute form of both.
	base := strings.TrimRight(p.svc.BaseURL(), "/")
	if htu == base+r.URL.Path {
		return true
	}
	return htu == p.issuer+r.URL.Path
}

// bearerScheme reports the authentication scheme of an Authorization header.
func bearerScheme(value string) (scheme, token string) {
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.ToLower(parts[0]), strings.TrimSpace(parts[1])
}

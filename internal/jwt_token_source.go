package internal

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

func JwtCallbackTokenSource(callback func() (string, error)) oauth2.TokenSource {
	return &jwtCallbackTokenSource{
		callback: callback,
	}
}

type jwtCallbackTokenSource struct {
	callback func() (string, error)
}

func (s *jwtCallbackTokenSource) Token() (*oauth2.Token, error) {
	log.Debug().Msg("Getting new token from callback")
	tokenString, err := s.callback()
	if err != nil {
		return nil, err
	}
	c := jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tokenString, &c)
	if err != nil {
		return nil, err
	}
	token := oauth2.Token{
		AccessToken: tokenString,
		Expiry:      c.ExpiresAt.Time,
	}

	log.Debug().Msgf("New token expires on %v", token.Expiry)
	return &token, nil
}

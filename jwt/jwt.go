package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type claims struct {
	Hash string `json:"operator:hash"`
	jwt.StandardClaims
}

type Issuer struct {
	sm  jwt.SigningMethod
	key []byte
	iss string
	aud string
	dur time.Duration
}

func NewIssuer(key []byte, iss, aud string, dur time.Duration) *Issuer {
	return &Issuer{sm: jwt.SigningMethodHS256, key: key, iss: iss, aud: aud, dur: dur}
}

func (i *Issuer) Token(hash string) (string, error) {
	t := jwt.NewWithClaims(i.sm, &claims{
		hash,
		jwt.StandardClaims{
			Issuer:    i.iss,
			Audience:  i.aud,
			ExpiresAt: time.Now().Add(i.dur).Unix(),
		},
	})

	return t.SignedString(i.key)
}

func (i *Issuer) Validate(token string) (string, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if t == nil {
			return nil, errors.New("Token is nil")
		}

		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		return i.key, nil
	})

	if err != nil || t == nil || !t.Valid {
		return "", errors.New("Invalid jwt token")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Invalid jwt claims")
	}

	if iss, ok := claims["iss"]; !ok || iss.(string) != i.iss {
		return "", fmt.Errorf("Invalid `iss` claim: %v", iss)
	}

	if aud, ok := claims["aud"]; !ok || aud.(string) != i.aud {
		return "", fmt.Errorf("Invalid `aud` claim: %v", aud)
	}

	hash, ok := claims["operator:hash"]
	if !ok || hash.(string) == "" {
		return "", fmt.Errorf("Invalid `operator:hash` claim: %v", hash)
	}

	return hash.(string), nil
}

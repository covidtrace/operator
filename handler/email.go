package handler

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/operator/storage"
	"github.com/covidtrace/operator/util"
	"github.com/google/uuid"
)

type emailHandler struct {
	bucket      storage.Bucket
	issuer      *jwt.Issuer
	refresh     *jwt.Issuer
	codeLength  int
	hashSalt    string
	fromAddress string
}

func NewEmail(bucket storage.Bucket, jwtSigningKey []byte, iss, aud string, td, rd time.Duration) Handler {
	issuer := jwt.NewIssuer(jwtSigningKey, iss, aud, td)
	refresh := issuer.WithDur(rd)

	return &emailHandler{
		bucket:      bucket,
		issuer:      issuer,
		refresh:     refresh,
		codeLength:  8,
		hashSalt:    util.GetEnvVar("HASH_SALT"),
		fromAddress: util.GetEnvVar("EMAIL_FROM_ADDRESS"),
	}
}

func (h *emailHandler) Issuer() *jwt.Issuer {
	return h.issuer
}

func (h *emailHandler) Refresher() *jwt.Issuer {
	return h.refresh
}

func (h *emailHandler) Bucket() storage.Bucket {
	return h.bucket
}

type emailReq struct {
	Email string `json:"email"`
}

func (h *emailHandler) TokenMeta(ctx context.Context, r *http.Request) (*tokenMeta, error) {
	if r.Body == nil {
		return nil, errors.New("missing request body")
	}
	defer r.Body.Close()

	var req emailReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err == io.EOF {
		return nil, errors.New("missing request body")
	}

	if err != nil {
		return nil, errors.New("error parsing request body")
	}

	if req.Email == "" {
		return nil, errors.New("missing email")
	}

	// TODO email whitelist

	key, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.New("error generating key")
	}

	digits := make([]string, h.codeLength)
	rand.Seed(int64(key.ID()))

	for i := 0; i < h.codeLength; i++ {
		digits[i] = fmt.Sprintf("%v", rand.Int()%10)
	}
	code := strings.Join(digits, "")

	components := []string{h.hashSalt, req.Email}

	hash := sha512.New()
	for _, component := range components {
		if _, err := io.WriteString(hash, component); err != nil {
			return nil, errors.New("error updating hash")
		}
	}

	return &tokenMeta{
		Code: code,
		Hash: base64.StdEncoding.EncodeToString(hash.Sum(nil)),
		dest: req.Email,
		key:  key.String(),
	}, nil
}

func (h *emailHandler) Dispatch(context.Context, *tokenMeta) error {
	// TODO this
	return nil
}

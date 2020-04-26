package handler

import (
	"context"
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
	bucket      storage.JSONBucket
	whitelist   storage.Bucket
	issuer      *jwt.Issuer
	refresh     *jwt.Issuer
	codeLength  int
	fromAddress string
	role        string
}

func NewEmail(bucket storage.JSONBucket, jwtSigningKey []byte, iss, aud string, td, rd time.Duration) (Handler, error) {
	issuer := jwt.NewIssuer(jwtSigningKey, iss, aud, td)
	refresh := issuer.WithDur(rd)

	whitelist, err := storage.NewBucket(util.GetEnvVar("CLOUD_STORAGE_WHITELIST_BUCKET"))
	if err != nil {
		return nil, err
	}

	return &emailHandler{
		bucket:      bucket,
		whitelist:   whitelist,
		issuer:      issuer,
		refresh:     refresh,
		codeLength:  8,
		fromAddress: util.GetEnvVar("EMAIL_FROM_ADDRESS"),
		role:        util.GetEnvVar("JWT_ELEVATED_ROLE"),
	}, nil
}

func (h *emailHandler) ID() string {
	return "emailhandler"
}

func (h *emailHandler) Issuer() *jwt.Issuer {
	return h.issuer
}

func (h *emailHandler) Refresher() *jwt.Issuer {
	return h.refresh
}

func (h *emailHandler) Bucket() storage.JSONBucket {
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

	if reader, err := h.whitelist.Get(ctx, strings.ToLower(req.Email)); err != nil {
		return nil, errors.New("error checking email whitelist")
	} else if reader == nil {
		return nil, errors.New("email not in whitelist")
	} else {
		if err := reader.Close(); err != nil {
			return nil, errors.New("error closing whitelist reader")
		}
	}

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

	return &tokenMeta{
		Code:       code,
		Identifier: req.Email,
		Role:       h.role,
		dispatch:   req.Email,
		key:        key.String(),
	}, nil
}

func (h *emailHandler) Dispatch(context.Context, *tokenMeta) error {
	// TODO this
	return nil
}

func (h *emailHandler) Identifier(tm tokenMeta) string {
	return tm.Identifier
}

func (h *emailHandler) Role(tm tokenMeta) string {
	return tm.Role
}

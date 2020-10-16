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
	"github.com/covidtrace/utils/env"
	"github.com/google/uuid"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type sendgridConfig struct {
	address    string
	name       string
	apiKey     string
	templateID string
}

type emailHandler struct {
	bucket     storage.JSONBucket
	whitelist  storage.Bucket
	issuer     *jwt.Issuer
	refresh    *jwt.Issuer
	codeLength int
	role       string
	sendgrid   sendgridConfig
}

func NewEmail(bucket storage.JSONBucket, jwtSigningKey []byte, iss, aud string, td, rd time.Duration) (Handler, error) {
	issuer := jwt.NewIssuer(jwtSigningKey, iss, aud, td)
	refresh := issuer.WithDur(rd)

	whitelist, err := storage.NewBucket(env.MustGet("CLOUD_STORAGE_WHITELIST_BUCKET"))
	if err != nil {
		return nil, err
	}

	return &emailHandler{
		bucket:     bucket,
		whitelist:  whitelist,
		issuer:     issuer,
		refresh:    refresh,
		codeLength: 8,
		role:       env.MustGet("JWT_ELEVATED_ROLE"),
		sendgrid: sendgridConfig{
			address:    env.MustGet("EMAIL_FROM_ADDRESS"),
			name:       env.MustGet("EMAIL_FROM_NAME"),
			apiKey:     env.MustGet("SENDGRID_API_KEY"),
			templateID: env.MustGet("SENDGRID_DYNAMIC_TEMPLATE_ID"),
		},
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

func (h *emailHandler) Dispatch(ctx context.Context, tm *tokenMeta) error {
	m := mail.NewV3Mail()
	m.SetTemplateID(h.sendgrid.templateID)
	m.SetFrom(mail.NewEmail(h.sendgrid.name, h.sendgrid.address))

	p := mail.NewPersonalization()
	p.AddTos(&mail.Email{Address: tm.dispatch})
	p.SetDynamicTemplateData("code", tm.Code)

	m.AddPersonalizations(p)

	req := sendgrid.GetRequest(h.sendgrid.apiKey, "/v3/mail/send", "https://api.sendgrid.com")
	req.Method = "POST"
	req.Body = mail.GetRequestBody(m)

	res, err := sendgrid.API(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected sendgrid http status: %v", res.StatusCode)
	}

	return nil
}

func (h *emailHandler) Identifier(tm tokenMeta) string {
	return tm.Identifier
}

func (h *emailHandler) Role(tm tokenMeta) string {
	return tm.Role
}

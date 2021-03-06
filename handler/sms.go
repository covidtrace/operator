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
	"net/url"
	"strings"
	"time"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/operator/storage"
	"github.com/covidtrace/utils/env"
	"github.com/google/uuid"
	"github.com/kevinburke/twilio-go"
)

type twilioConfig struct {
	from    string
	message *twilio.MessageService
	lookup  *twilio.LookupPhoneNumbersService
}

type smsHandler struct {
	bucket     storage.JSONBucket
	issuer     *jwt.Issuer
	refresh    *jwt.Issuer
	codeLength int
	hashSalt   string
	twilio     twilioConfig
}

func NewSMS(bucket storage.JSONBucket, jwtSigningKey []byte, iss, aud string, td, rd time.Duration) Handler {
	issuer := jwt.NewIssuer(jwtSigningKey, iss, aud, td)
	refresh := issuer.WithDur(rd)

	tc := twilio.NewClient(env.MustGet("TWILIO_ACCOUNT_SID"), env.MustGet("TWILIO_AUTH_TOKEN"), nil)
	tlc := twilio.NewLookupClient(env.MustGet("TWILIO_ACCOUNT_SID"), env.MustGet("TWILIO_AUTH_TOKEN"), nil)

	return &smsHandler{
		bucket:     bucket,
		issuer:     issuer,
		refresh:    refresh,
		codeLength: 6,
		hashSalt:   env.MustGet("HASH_SALT"),
		twilio: twilioConfig{
			from:    env.MustGet("TWILIO_FROM_NUMBER"),
			message: tc.Messages,
			lookup:  tlc.LookupPhoneNumbers,
		},
	}
}

func (h *smsHandler) ID() string {
	return "smshandler"
}

func (h *smsHandler) Issuer() *jwt.Issuer {
	return h.issuer
}

func (h *smsHandler) Refresher() *jwt.Issuer {
	return h.refresh
}

func (h *smsHandler) Bucket() storage.JSONBucket {
	return h.bucket
}

type phoneReq struct {
	Phone string `json:"phone"`
}

func (h *smsHandler) TokenMeta(ctx context.Context, r *http.Request) (*tokenMeta, error) {
	if r.Body == nil {
		return nil, errors.New("missing request body")
	}
	defer r.Body.Close()

	var req phoneReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err == io.EOF {
		return nil, errors.New("missing request body")
	}

	if err != nil {
		return nil, errors.New("error parsing request body")
	}

	if req.Phone == "" {
		return nil, errors.New("missing phone number")
	}

	qp := url.Values{}
	qp.Add("CountryCode", "US")
	qp.Add("Type", "carrier")

	lpn, err := h.twilio.lookup.Get(ctx, req.Phone, qp)
	if err != nil || lpn.CountryCode != "US" || lpn.Carrier.Type != "mobile" {
		return nil, errors.New("error with phone number lookup")
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

	components := []string{
		h.hashSalt,
		lpn.Carrier.Type,
		lpn.Carrier.MobileCountryCode,
		lpn.Carrier.MobileNetworkCode,
		lpn.Carrier.Name,
		lpn.CountryCode,
		lpn.PhoneNumber,
	}

	hash := sha512.New()
	for _, component := range components {
		if _, err := io.WriteString(hash, component); err != nil {
			return nil, errors.New("error updating hash")
		}
	}

	return &tokenMeta{
		Code:     code,
		Hash:     base64.StdEncoding.EncodeToString(hash.Sum(nil)),
		dispatch: req.Phone,
		key:      key.String(),
	}, nil
}

func (h *smsHandler) Dispatch(ctx context.Context, tm *tokenMeta) error {
	if tm.dispatch == "" {
		return errors.New("invalid phone number")
	}

	if _, err := h.twilio.message.SendMessage(
		h.twilio.from,
		tm.dispatch,
		fmt.Sprintf("Your COVID Trace verification code is %s", tm.Code),
		nil,
	); err != nil {
		return errors.New("error sending SMS")
	}

	return nil
}

func (h *smsHandler) Identifier(tokenMeta) string {
	return ""
}

func (h *smsHandler) Role(tokenMeta) string {
	return "app_user"
}

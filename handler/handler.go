package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/operator/storage"
	httputils "github.com/covidtrace/utils/http"
	"github.com/julienschmidt/httprouter"
)

type Handler interface {
	ID() string
	Issuer() *jwt.Issuer
	Refresher() *jwt.Issuer
	Identifier(tokenMeta) string
	Role(tokenMeta) string
	Bucket() storage.JSONBucket
	TokenMeta(context.Context, *http.Request) (*tokenMeta, error)
	Dispatch(context.Context, *tokenMeta) error
}

type tokenMeta struct {
	key, dispatch string

	HandlerID  string `json:"handler"`
	Identifier string `json:"identifier,omitempty"`
	Code       string `json:"code"`
	Hash       string `json:"hash,omitempty"`
	Role       string `json:"role,omitempty"`
}

type initRes struct {
	Token string `json:"token"`
}

type verifyReq struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

type verifyRes struct {
	Token   string `json:"token"`
	Refresh string `json:"refresh"`
}

func Init(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		tm, err := h.TokenMeta(context.Background(), r)
		if err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		if tm == nil {
			httputils.ReplyError(w, errors.New("nil TokenMeta"), http.StatusBadRequest)
			return
		}

		tm.HandlerID = h.ID()
		if err := h.Bucket().PutJSON(ctx, fmt.Sprintf("%s.json", tm.key), tm); err != nil {
			httputils.ReplyError(w, errors.New("error persisting token and code"), http.StatusBadRequest)
			return
		}

		if err := h.Dispatch(ctx, tm); err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		httputils.ReplyJSON(w, initRes{Token: tm.key}, http.StatusOK)
	}
}

func Verify(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var req verifyReq
		if r.Body == nil {
			httputils.ReplyError(w, errors.New("missing request body"), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&req)
		if err == io.EOF {
			httputils.ReplyError(w, errors.New("missing request body"), http.StatusBadRequest)
			return
		}

		if err != nil {
			httputils.ReplyError(w, errors.New("error parsing request body"), http.StatusBadRequest)
			return
		}

		key := fmt.Sprintf("%s.json", req.Token)
		var tm tokenMeta
		found, err := h.Bucket().GetJSON(ctx, key, &tm)
		if err != nil {
			httputils.ReplyError(w, errors.New("error fetching token metadata"), http.StatusBadRequest)
			return
		}
		if !found {
			httputils.ReplyError(w, errors.New("no token metadata found"), http.StatusNotFound)
			return
		}

		if tm.HandlerID != h.ID() {
			httputils.ReplyError(w, errors.New("invalid handler"), http.StatusBadRequest)
			return
		}

		if tm.Code != req.Code {
			httputils.ReplyError(w, errors.New("invalid code"), http.StatusBadRequest)
			return
		}

		token, err := h.Issuer().Token(tm.Hash, 0, h.Identifier(tm), h.Role(tm))
		if err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		refresh, err := h.Issuer().Token(tm.Hash, 0, h.Identifier(tm), h.Role(tm))
		if err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		if _, err := h.Bucket().Delete(ctx, key); err != nil {
			httputils.ReplyError(w, errors.New("error deleting metadata"), http.StatusBadRequest)
			return
		}

		httputils.ReplyJSON(w, verifyRes{Token: token, Refresh: refresh}, http.StatusOK)
	}
}

func Refresh(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		query := r.URL.Query()
		code := query.Get("code")
		if code == "" {
			httputils.ReplyError(w, errors.New("missing code parameter"), http.StatusUnauthorized)
			return
		}

		claims, err := h.Issuer().Validate(code)
		if err != nil {
			httputils.ReplyError(w, err, http.StatusUnauthorized)
			return
		}

		token, err := h.Issuer().Token(
			claims.Hash,
			claims.Refreshed+1,
			claims.Identifier,
			claims.Role,
		)
		if err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		refresh, err := h.Refresher().Token(
			claims.Hash,
			claims.Refreshed+1,
			claims.Identifier,
			claims.Role,
		)
		if err != nil {
			httputils.ReplyError(w, err, http.StatusBadRequest)
			return
		}

		httputils.ReplyJSON(w, verifyRes{Token: token, Refresh: refresh}, http.StatusOK)
	}
}

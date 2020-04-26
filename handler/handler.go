package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/operator/storage"
	"github.com/covidtrace/operator/util"
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
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		if tm == nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "nil token"})
			return
		}

		tm.HandlerID = h.ID()
		if err := h.Bucket().PutJSON(ctx, fmt.Sprintf("%s.json", tm.key), tm); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error persisting token and code"})
			return
		}

		if err := h.Dispatch(ctx, tm); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		util.ReplyJSON(w, http.StatusOK, initRes{Token: tm.key})
	}
}

func Verify(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var req verifyReq
		if r.Body == nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&req)
		if err == io.EOF {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Missing request body"})
			return
		}

		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error parsing request body"})
			return
		}

		key := fmt.Sprintf("%s.json", req.Token)
		var tm tokenMeta
		found, err := h.Bucket().GetJSON(ctx, key, &tm)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error fetching token metadata"})
			return
		}
		if !found {
			util.ReplyJSON(w, http.StatusNotFound, util.Error{Message: "No token metadata found"})
			return
		}

		if tm.HandlerID != h.ID() {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Invalid handler"})
			return
		}

		if tm.Code != req.Code {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Invalid code"})
			return
		}

		token, err := h.Issuer().Token(tm.Hash, 0, h.Identifier(tm), h.Role(tm))
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		refresh, err := h.Issuer().Token(tm.Hash, 0, h.Identifier(tm), h.Role(tm))
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		if _, err := h.Bucket().Delete(ctx, key); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error deleting metadata"})
			return
		}

		util.ReplyJSON(w, http.StatusOK, verifyRes{Token: token, Refresh: refresh})
	}
}

func Refresh(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		query := r.URL.Query()
		code := query.Get("code")
		if code == "" {
			util.ReplyJSON(w, http.StatusUnauthorized, util.Error{Message: "Missing code parameter"})
			return
		}

		claims, err := h.Issuer().Validate(code)
		if err != nil {
			util.ReplyJSON(w, http.StatusUnauthorized, util.Error{Message: err.Error()})
			return
		}

		token, err := h.Issuer().Token(
			claims.Hash,
			claims.Refreshed+1,
			claims.Identifier,
			claims.Role,
		)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		refresh, err := h.Refresher().Token(
			claims.Hash,
			claims.Refreshed+1,
			claims.Identifier,
			claims.Role,
		)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		util.ReplyJSON(w, http.StatusOK, verifyRes{Token: token, Refresh: refresh})
	}
}

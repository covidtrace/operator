package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/covidtrace/operator/jwt"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	twilio "github.com/kevinburke/twilio-go"
)

func getEnvVar(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Errorf("%s is required env var", key))
	}

	return value
}

var tokenIssuer *jwt.Issuer
var refreshTokenIssuer *jwt.Issuer

var codeLength int = 6

var storageClient *storage.Client
var storageBucket *storage.BucketHandle

var twilioMessages *twilio.MessageService
var twilioLookup *twilio.LookupPhoneNumbersService
var twilioFromNumber string

func init() {
	var err error

	td, err := time.ParseDuration(getEnvVar("JWT_TOKEN_DURATION"))
	if err != nil {
		panic(err)
	}

	tokenIssuer = jwt.NewIssuer(
		[]byte(getEnvVar("JWT_SIGNING_KEY")),
		"covidtrace/operator",
		"covidtrace/token",
		td,
	)

	rd, err := time.ParseDuration(getEnvVar("JWT_REFRESH_DURATION"))
	if err != nil {
		panic(err)
	}

	refreshTokenIssuer = jwt.NewIssuer(
		[]byte(getEnvVar("JWT_SIGNING_KEY")),
		"covidtrace/operator",
		"covidtrace/refresh",
		rd,
	)

	mc := twilio.NewClient(getEnvVar("TWILIO_ACCOUNT_SID"), getEnvVar("TWILIO_AUTH_TOKEN"), nil)
	twilioMessages = mc.Messages

	lookupClient := twilio.NewLookupClient(getEnvVar("TWILIO_ACCOUNT_SID"), getEnvVar("TWILIO_AUTH_TOKEN"), nil)
	twilioLookup = lookupClient.LookupPhoneNumbers

	twilioFromNumber = getEnvVar("TWILIO_FROM_NUMBER")

	c, err := storage.NewClient(context.Background())
	if err != nil {
		panic(err)
	}

	storageClient = c
	storageBucket = storageClient.Bucket("covidtrace-operator")
}

type errMessage struct {
	Message string `json:"status"`
}

type initBody struct {
	PhoneNumber string `json:"phone"`
}

type initResp struct {
	Token string `json:"token"`
}

type tokenMetadata struct {
	Code string `json:"code"`
	Hash string `json:"hash"`
}

type verifyBody struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

type verifyResp struct {
	Token   string `json:"token"`
	Refresh string `json:"refresh"`
}

func replyJSON(w http.ResponseWriter, code int, r interface{}) {
	b, err := json.Marshal(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(code)
	io.Copy(w, bytes.NewReader(b))
}

func main() {
	router := httprouter.New()

	router.POST("/init", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var ib initBody
		if r.Body == nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&ib)
		if err == io.EOF {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}

		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error parsing request body"})
			return
		}

		if ib.PhoneNumber == "" {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing phone number"})
			return
		}

		qp := url.Values{}
		qp.Add("CountryCode", "US")
		qp.Add("Type", "carrier")
		lpn, err := twilioLookup.Get(ctx, ib.PhoneNumber, qp)
		if err != nil || lpn.CountryCode != "US" || lpn.Carrier.Type != "mobile" {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error with phone number lookup"})
			return
		}

		key, err := uuid.NewRandom()
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error generating key"})
			return
		}

		digits := make([]string, codeLength)
		rand.Seed(int64(key.ID()))

		for i := 0; i < codeLength; i++ {
			digits[i] = fmt.Sprintf("%v", rand.Int()%10)
		}
		code := strings.Join(digits, "")

		components := []string{
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
				replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error updating hash"})
				return
			}
		}

		tm := tokenMetadata{Code: code, Hash: base64.StdEncoding.EncodeToString(hash.Sum(nil))}

		ow := storageBucket.Object(fmt.Sprintf("%s.json", key)).NewWriter(ctx)
		if err := json.NewEncoder(ow).Encode(tm); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error persisting token and code"})
			return
		}

		if err := ow.Close(); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error persisting token and code"})
			return
		}

		_, err = twilioMessages.SendMessage(
			twilioFromNumber,
			ib.PhoneNumber,
			fmt.Sprintf("Your COVID Trace verification code is %s", code),
			nil,
		)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error sending SMS"})
			return
		}

		replyJSON(w, http.StatusOK, initResp{Token: key.String()})
	})

	router.POST("/verify", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var vb verifyBody
		if r.Body == nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&vb)
		if err == io.EOF {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}

		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error parsing request body"})
			return
		}

		var tm tokenMetadata
		oh := storageBucket.Object(fmt.Sprintf("%s.json", vb.Token))

		or, err := oh.NewReader(ctx)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if err := json.NewDecoder(or).Decode(&tm); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if err := or.Close(); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if tm.Code != vb.Code {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Invalid code"})
			return
		}

		token, err := tokenIssuer.Token(tm.Hash)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: err.Error()})
			return
		}

		refresh, err := refreshTokenIssuer.Token(tm.Hash)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: err.Error()})
			return
		}

		if err := oh.Delete(ctx); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error deleting metadata"})
			return
		}

		replyJSON(w, http.StatusOK, verifyResp{Token: token, Refresh: refresh})
	})

	router.POST("/refresh", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		qp := r.URL.Query()
		code := qp.Get("code")
		if code == "" {
			replyJSON(w, http.StatusUnauthorized, errMessage{Message: "Missing code parameter"})
			return
		}

		hash, err := refreshTokenIssuer.Validate(code)
		if err != nil {
			replyJSON(w, http.StatusUnauthorized, errMessage{Message: err.Error()})
			return
		}

		token, err := tokenIssuer.Token(hash)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: err.Error()})
			return
		}

		refresh, err := refreshTokenIssuer.Token(hash)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: err.Error()})
			return
		}

		replyJSON(w, http.StatusOK, verifyResp{Token: token, Refresh: refresh})
	})

	router.PanicHandler = func(w http.ResponseWriter, _ *http.Request, _ interface{}) {
		http.Error(w, "Unknown error", http.StatusBadRequest)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/covidtrace/operator/handler"
	"github.com/covidtrace/operator/storage"
	"github.com/covidtrace/operator/util"
	"github.com/julienschmidt/httprouter"
)

var tokenHandler handler.Handler
var elevatedHandler handler.Handler

func init() {
	var err error

	jsk := []byte(util.GetEnvVar("JWT_SIGNING_KEY"))
	tns := util.GetEnvVar("JWT_NAMESPACE")

	ttd, err := time.ParseDuration(util.GetEnvVar("JWT_TOKEN_DURATION"))
	if err != nil {
		panic(err)
	}

	trd, err := time.ParseDuration(util.GetEnvVar("JWT_REFRESH_DURATION"))
	if err != nil {
		panic(err)
	}

	tb, err := storage.NewJSONBucket(util.GetEnvVar("CLOUD_STORAGE_BUCKET"))
	if err != nil {
		panic(err)
	}

	iss := fmt.Sprintf("%s/operator", tns)
	tokenHandler = handler.NewSMS(tb, jsk, iss, fmt.Sprintf("%s/token", tns), ttd, trd)

	etd, err := time.ParseDuration(util.GetEnvVar("JWT_ELEVATED_TOKEN_DURATION"))
	if err != nil {
		panic(err)
	}

	erd, err := time.ParseDuration(util.GetEnvVar("JWT_ELEVATED_REFRESH_DURATION"))
	if err != nil {
		panic(err)
	}

	elevatedHandler, err = handler.NewEmail(tb, jsk, iss, fmt.Sprintf("%s/elevated", tns), etd, erd)
	if err != nil {
		panic(err)
	}
}

func main() {
	router := httprouter.New()

	// General covidtrace/token token handlers
	router.POST("/init", handler.Init(tokenHandler))
	router.POST("/verify", handler.Verify(tokenHandler))
	router.POST("/refresh", handler.Refresh(tokenHandler))

	// General covidtrace/elevated token handlers
	router.POST("/elevated/init", handler.Init(elevatedHandler))
	router.POST("/elevated/verify", handler.Verify(elevatedHandler))
	router.POST("/elevated/refresh", handler.Refresh(elevatedHandler))

	router.PanicHandler = func(w http.ResponseWriter, _ *http.Request, _ interface{}) {
		http.Error(w, "Unknown error", http.StatusBadRequest)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}

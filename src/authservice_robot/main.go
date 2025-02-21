// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/dghubble/gologin/v2"
	"github.com/dghubble/gologin/v2/github"
	"github.com/dghubble/gologin/v2/google"
	"github.com/dghubble/sessions"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
	googleOAuth2 "golang.org/x/oauth2/google"
	"google.golang.org/grpc"
)

const (
	port            = "8080"
	defaultCurrency = "USD"
	cookieMaxAge    = 60 * 60 * 48

	cookiePrefix    = "shop_"
	cookieSessionID = cookiePrefix + "session-id"
	cookieCurrency  = cookiePrefix + "currency"

	sessionSecret    = "example cookie signing secret"
	sessionName      = "example-app"
	sessionLoginType = "userLoginType"
	sessionUserKey   = "userID"
	sessionUsername  = "userName"
	sessionUserEmail = "userEmail"

	userdbName = "usvcs_userdb"
)

var (
	whitelistedCurrencies = map[string]bool{
		"USD": true,
		"EUR": true,
		"CAD": true,
		"JPY": true,
		"GBP": true,
		"TRY": true}
	db *sql.DB
)

// sessionStore encodes and decodes session data stored in signed cookies
var sessionStore = sessions.NewCookieStore[string](sessions.DebugCookieConfig, []byte(sessionSecret), nil)

// Config configures the main ServeMux.
type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	GithubClientID     string
	GithubClientSecret string
}

type UserInfo struct {
	loginType string
	name      string
	email     string
	password  string
}

type ctxKeySessionID struct{}

type frontendServer struct {
	productCatalogSvcAddr string
	productCatalogSvcConn *grpc.ClientConn

	currencySvcAddr string
	currencySvcConn *grpc.ClientConn

	cartSvcAddr string
	cartSvcConn *grpc.ClientConn

	recommendationSvcAddr string
	recommendationSvcConn *grpc.ClientConn

	checkoutSvcAddr string
	checkoutSvcConn *grpc.ClientConn

	shippingSvcAddr string
	shippingSvcConn *grpc.ClientConn
	// shippingFreeSvcConn *grpc.ClientConn

	adSvcAddr string
	adSvcConn *grpc.ClientConn

	collectorAddr string
	collectorConn *grpc.ClientConn
}

// issueSession issues a cookie session after successful Google login
func googleIssueSession(log logrus.FieldLogger) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		log.Infof("Hello I am entering googleIssueSession")
		ctx := req.Context()
		googleUser, err := google.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Infof("googleUser: %+v", googleUser)
		// 2. Implement a success handler to issue some form of session
		session := sessionStore.New(sessionName)
		session.Set(sessionLoginType, "Google")
		session.Set(sessionUserKey, googleUser.Id)
		session.Set(sessionUsername, googleUser.Name)
		session.Set(sessionUserEmail, googleUser.Email)
		log.Infof("session: %+v", session)
		if err := session.Save(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// issueSession issues a cookie session after successful Google login
func githubIssueSession(log logrus.FieldLogger) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		log.Infof("Hello I am entering githubIssueSession")
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Infof("githubUser: %+v", githubUser)
		log.Infof("githubID: %+v, %+v, %+v", githubUser.ID, *githubUser.ID, strconv.FormatInt(*githubUser.ID, 10))
		log.Infof("githubName: %+v, %+v", githubUser.Name, *githubUser.Name)
		log.Infof("githubEmail: %+v, %+v", githubUser.Email, *githubUser.Email)
		// 2. Implement a success handler to issue some form of session
		session := sessionStore.New(sessionName)
		session.Set(sessionLoginType, "Github")
		session.Set(sessionUserKey, strconv.FormatInt(*githubUser.ID, 10))
		session.Set(sessionUsername, *githubUser.Name)
		session.Set(sessionUserEmail, *githubUser.Email)
		log.Infof("session: %+v", session)
		if err := session.Save(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func isAuthenticated(r *http.Request, log logrus.FieldLogger) bool {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil {
		// welcome with login button
		log.Infof("You are not logged in!")
		return false
	}

	log.Infof("You are logged in %s!", session.Get(sessionUsername))

	fwdHostName := r.Header.Get("X-forwarded-Host")
	log.Infof("fwdHostName is %v", fwdHostName)
	if fwdHostName != "" {
		return true
	}

	r.Header.Set("X-forwarded-Host", "Default")
	fwdHostName = r.Header.Get("X-forwarded-Host")
	log.Infof("fwdHostName is %v", fwdHostName)

	if session.Get(sessionLoginType) == "Google" && strings.Contains(session.Get(sessionUsername), "Nithin") {
		// This is for free shipping
		log.Infof("Setting fwdHostName header for user Nithin to Nithin")
		r.Header.Set("X-forwarded-Host", "Nithin")
		fwdHostName = r.Header.Get("X-forwarded-Host")
		log.Infof("fwdHostName is %v", fwdHostName)
		return true
	} else if session.Get(sessionLoginType) == "Google" && strings.Contains(session.Get(sessionUsername), "Novus") {
		// This is for showing recommendations
		log.Infof("Setting fwdHostName header for user Temp to Novus")
		r.Header.Set("X-forwarded-Host", "Novus")
		fwdHostName = r.Header.Get("X-forwarded-Host")
		log.Infof("fwdHostName is %v", fwdHostName)
		return true
	} else {
		log.Infof("Set fwdHostName header for all other users to Default")
		fwdHostName = r.Header.Get("X-forwarded-Host")
		log.Infof("fwdHostName is %v", fwdHostName)
		return true
	}

	return true
}

func handleAuth(f http.HandlerFunc, log logrus.FieldLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if valid := isAuthenticated(r, log); !valid {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "Invalid token or Client not authenticated.")
			return // this return is *very* important
		}
		// Now call the actual handler, which is authenticated
		f(w, r)
	}
}

func initializeUserDb(log logrus.FieldLogger) error {
	err := db.Ping()
	if err != nil {
		log.Fatal("Ping to mysql server failed: %s", err.Error())
		return err
	}

	result, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + userdbName)
	if err != nil {
		log.Fatalf("Create database %s failed. Err: %s", userdbName, err.Error())
	}
	log.Infof("Result: %+v", result)

	result, err = db.Exec("USE " + userdbName)
	if err != nil {
		log.Fatalf("USE database %s failed. Err: %s", userdbName, err.Error())
	}
	log.Infof("Result: %+v", result)

	result, err = db.Exec("CREATE TABLE IF NOT EXISTS userInfo (login_type VARCHAR(32) NOT NULL, name VARCHAR(256), email VARCHAR(256) NOT NULL PRIMARY KEY, password VARCHAR(256) NOT NULL)")
	if err != nil {
		log.Fatalf("CREATE TABLE userInfo failed. Err: %s", err.Error())
	}
	log.Infof("Result: %+v", result)

	return err
}

func main() {
	var err error

	ctx := context.Background()
	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.JSONFormatter{
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
		TimestampFormat: time.RFC3339Nano,
	}
	log.Out = os.Stdout

	svc := new(frontendServer)

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))

	if os.Getenv("ENABLE_TRACING") == "1" {
		log.Info("Tracing enabled.")
		initTracing(log, ctx, svc)
	} else {
		log.Info("Tracing disabled.")
	}

	if os.Getenv("ENABLE_PROFILER") == "1" {
		log.Info("Profiling enabled.")
		go initProfiling(log, "frontend", "1.0.0")
	} else {
		log.Info("Profiling disabled.")
	}

	srvPort := port
	if os.Getenv("PORT") != "" {
		srvPort = os.Getenv("PORT")
	}
	addr := os.Getenv("LISTEN_ADDR")

	// read credentials from environment variables if available
	config := &Config{
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GithubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GithubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	}
	// allow consumer credential flags to override config fields
	googleClientID := flag.String("google-client-id", "", "Google Client ID")
	googleClientSecret := flag.String("google-client-secret", "", "Google Client Secret")
	githubClientID := flag.String("github-client-id", "", "Github Client ID")
	githubClientSecret := flag.String("github-client-secret", "", "Github Client Secret")
	flag.Parse()
	if *googleClientID != "" {
		config.GoogleClientID = *googleClientID
	}
	if *googleClientSecret != "" {
		config.GoogleClientSecret = *googleClientSecret
	}
	if *githubClientID != "" {
		config.GithubClientID = *githubClientID
	}
	if *githubClientSecret != "" {
		config.GithubClientSecret = *githubClientSecret
	}

	log.Infof("Config: %+v", config)

	if config.GoogleClientID == "" {
		log.Fatal("Missing Google Client ID")
	}
	if config.GoogleClientSecret == "" {
		log.Fatal("Missing Google Client Secret")
	}
	if config.GithubClientID == "" {
		log.Fatal("Missing Github Client ID")
	}
	if config.GithubClientSecret == "" {
		log.Fatal("Missing Github Client Secret")
	}

	db, err = sql.Open("mysql", "root:test1234@tcp(mysql:3306)/")
	if err != nil {
		log.Fatal("Unable to fetch handle to mysql user database")
	}

	defer db.Close()

	initializeUserDb(log)

	mustMapEnv(&svc.productCatalogSvcAddr, "PRODUCT_CATALOG_SERVICE_ADDR")
	mustMapEnv(&svc.currencySvcAddr, "CURRENCY_SERVICE_ADDR")
	mustMapEnv(&svc.cartSvcAddr, "CART_SERVICE_ADDR")
	mustMapEnv(&svc.recommendationSvcAddr, "RECOMMENDATION_SERVICE_ADDR")
	mustMapEnv(&svc.checkoutSvcAddr, "CHECKOUT_SERVICE_ADDR")
	mustMapEnv(&svc.shippingSvcAddr, "SHIPPING_SERVICE_ADDR")
	mustMapEnv(&svc.adSvcAddr, "AD_SERVICE_ADDR")

	mustConnGRPC(ctx, &svc.currencySvcConn, svc.currencySvcAddr)
	mustConnGRPC(ctx, &svc.productCatalogSvcConn, svc.productCatalogSvcAddr)
	mustConnGRPC(ctx, &svc.cartSvcConn, svc.cartSvcAddr)
	mustConnGRPC(ctx, &svc.recommendationSvcConn, svc.recommendationSvcAddr)
	mustConnGRPC(ctx, &svc.shippingSvcConn, svc.shippingSvcAddr)
	// mustConnGRPC(ctx, &svc.shippingFreeSvcConn, "shippingfreeservice:50051")
	mustConnGRPC(ctx, &svc.checkoutSvcConn, svc.checkoutSvcAddr)
	mustConnGRPC(ctx, &svc.adSvcConn, svc.adSvcAddr)

	r := mux.NewRouter()
	s := r.PathPrefix("/").Subrouter()
	s.HandleFunc("/", svc.homeHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/login", svc.loginHandler).Methods(http.MethodGet)
	r.HandleFunc("/local/register", svc.localRegisterHandler).Methods(http.MethodPost)
	r.HandleFunc("/local/login", svc.localLoginHandler).Methods(http.MethodPost)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	r.HandleFunc("/product/{id}", svc.homeHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/cart", svc.homeHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/cart", svc.homeHandler).Methods(http.MethodPost)
	r.HandleFunc("/cart/empty", svc.homeHandler).Methods(http.MethodPost)
	r.HandleFunc("/setCurrency", svc.homeHandler).Methods(http.MethodPost)
	r.HandleFunc("/logout", svc.homeHandler).Methods(http.MethodGet)
	r.HandleFunc("/cart/checkout", svc.homeHandler).Methods(http.MethodPost)
	r.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "User-agent: *\nDisallow: /") })
	r.HandleFunc("/_healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/src/static"))))
	// 1. Register Login and Callback handlers
	googleOauth2Config := &oauth2.Config{
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		RedirectURL:  "http://multiusertest.novusbee.com:20080/google/callback",
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"profile", "email"},
	}
	githubOauth2Config := &oauth2.Config{
		ClientID:     config.GithubClientID,
		ClientSecret: config.GithubClientSecret,
		RedirectURL:  "http://multiusertest.novusbee.com:20080/github/callback",
		Endpoint:     githubOAuth2.Endpoint,
		Scopes:       []string{"profile", "email"},
	}
	// state param cookies require HTTPS by default; disable for localhost development
	stateConfig := gologin.DebugOnlyCookieConfig
	r.Handle("/google/login", google.StateHandler(stateConfig, google.LoginHandler(googleOauth2Config, nil)))
	r.Handle("/google/callback", google.StateHandler(stateConfig, google.CallbackHandler(googleOauth2Config, googleIssueSession(log), nil)))
	r.Handle("/github/login", github.StateHandler(stateConfig, github.LoginHandler(githubOauth2Config, nil)))
	r.Handle("/github/callback", github.StateHandler(stateConfig, github.CallbackHandler(githubOauth2Config, githubIssueSession(log), nil)))

	var handler http.Handler = r
	handler = &logHandler{log: log, next: handler}        // add logging
	handler = ensureSessionID(handler)                    // add session ID
	handler = otelhttp.NewHandler(handler, "authservice") // add OTel tracing

	log.Infof("starting server on " + addr + ":" + srvPort)
	log.Fatal(http.ListenAndServe(addr+":"+srvPort, handler))
}
func initStats(log logrus.FieldLogger) {
	// TODO(arbrown) Implement OpenTelemtry stats
}

func initTracing(log logrus.FieldLogger, ctx context.Context, svc *frontendServer) (*sdktrace.TracerProvider, error) {
	mustMapEnv(&svc.collectorAddr, "COLLECTOR_SERVICE_ADDR")
	mustConnGRPC(ctx, &svc.collectorConn, svc.collectorAddr)
	exporter, err := otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithGRPCConn(svc.collectorConn))
	if err != nil {
		log.Warnf("warn: Failed to create trace exporter: %v", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)

	return tp, err
}

func initProfiling(log logrus.FieldLogger, service, version string) {
	// TODO(ahmetb) this method is duplicated in other microservices using Go
	// since they are not sharing packages.
	for i := 1; i <= 3; i++ {
		log = log.WithField("retry", i)
		if err := profiler.Start(profiler.Config{
			Service:        service,
			ServiceVersion: version,
			// ProjectID must be set if not running on GCP.
			// ProjectID: "my-project",
		}); err != nil {
			log.Warnf("warn: failed to start profiler: %+v", err)
		} else {
			log.Info("started Stackdriver profiler")
			return
		}
		d := time.Second * 10 * time.Duration(i)
		log.Debugf("sleeping %v to retry initializing Stackdriver profiler", d)
		time.Sleep(d)
	}
	log.Warn("warning: could not initialize Stackdriver profiler after retrying, giving up")
}

func mustMapEnv(target *string, envKey string) {
	v := os.Getenv(envKey)
	if v == "" {
		panic(fmt.Sprintf("environment variable %q not set", envKey))
	}
	*target = v
}

func mustConnGRPC(ctx context.Context, conn **grpc.ClientConn, addr string) {
	var err error
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	*conn, err = grpc.DialContext(ctx, addr,
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()))
	if err != nil {
		panic(errors.Wrapf(err, "grpc: failed to connect %s", addr))
	}
}

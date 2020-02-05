package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	ctx    context.Context
	cancel context.CancelFunc
)

func init() {
	ctx, cancel = context.WithCancel(context.Background())
}

func stdout(msg string, fields ...interface{}) {
	fmt.Fprintf(os.Stdout, msg+"\n", fields...)
}

func stderr(msg string, fields ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", fields...)
}

func handleFunc(ctx context.Context, cfg *oauth2.Config, vfr *oidc.IDTokenVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// always shut down server after one request is handled
		defer cancel()

		fmt.Fprintf(w, "Please return to CLI...")

		stdout("Handling request...")

		v, _ := url.ParseQuery(r.URL.RawQuery)
		code := v.Get("code")

		if code == "" {
			fmt.Fprintf(w, "Failure! Please return to CLI...")

			stderr("OAuth2 failed...")

			error_type := v.Get("error")
			error_desc := v.Get("error_description")
			stderr("error = %s", error_type)
			stderr("error_description = %s", error_desc)
			return
		}

		stdout("Received auth code: %s", code)

		oauthTok, err := cfg.Exchange(ctx, code)
		if err != nil {
			stderr("OAuth2 failed...")
			stderr("error = unable to exchange auth code")
			stderr("error_description = %s", err)
		}

		stdout("Received access token: %s", oauthTok.AccessToken)

		rawIDToken, ok := oauthTok.Extra("id_token").(string)
		if !ok {
			stderr("OAuth2 failed...")
			stderr("error = failed to find id_token claim in OAuth2 token")
			return
		}

		idTok, err := vfr.Verify(ctx, rawIDToken)
		if err != nil {
			stderr("OIDC failed...")
			stderr("error = id_token could not be verified")
			stderr("error_description = %v", err)
			stderr("id_token = %s", rawIDToken)
			return
		}

		stdout("OIDC success...")
		stdout("subject = %s", idTok.Subject)

		stdout("id_token follows...")
		stdout("")
		stdout(rawIDToken)
	}
}

func main() {
	root := cobra.Command{
		Use:   "oidctl",
		Short: "OpenID Connect CLI toolkit",
	}

	issue := cobra.Command{
		Use:   "issue",
		Short: "request a new OIDC token",
		Args:  cobra.NoArgs,
	}

	root.AddCommand(&issue)

	var issuer, clientID, clientSecret string
	issue.Flags().StringVarP(&issuer, "issuer", "", "", "OIDC issuer URL")
	issue.MarkFlagRequired("issuer")
	issue.Flags().StringVarP(&clientID, "client-id", "", "", "OIDC client ID")
	issue.MarkFlagRequired("client-id")
	issue.Flags().StringVarP(&clientSecret, "client-secret", "", "", "OIDC client secret")
	issue.MarkFlagRequired("client-secret")

	issue.Run = func(cmd *cobra.Command, args []string) {
		prv, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			stderr("unable to create OIDC provider: %v", err)
			os.Exit(1)
		}

		cfg := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"openid", "profile"},
			Endpoint:     prv.Endpoint(),
			RedirectURL:  "http://localhost:8080/authorization-code/callback",
		}

		vfr := prv.Verifier(&oidc.Config{ClientID: cfg.ClientID})

		// Redirect user to consent page to ask for permission
		// for the scopes specified above.
		url := cfg.AuthCodeURL("state", oauth2.AccessTypeOffline)

		open.Run(url)

		mux := http.NewServeMux()
		mux.HandleFunc("/authorization-code/callback", handleFunc(ctx, &cfg, vfr))

		var srv http.Server
		srv.Addr = "127.0.0.1:8080"
		srv.Handler = mux

		go func() {
			// once context is canceled, shut down the HTTP server
			<-ctx.Done()
			srv.Shutdown(ctx)
		}()

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stderr("HTTP server aborted: %v", err)
			os.Exit(1)
		}
	}

	root.Execute()
}

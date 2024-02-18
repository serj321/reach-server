package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type users struct {
	email string
	sub string
	jwtToken string
}

func init() {
    if err := godotenv.Load(); err != nil {
        log.Fatalf("Error loading .env file: %v", err)
    }
}

func randString(nByte int) (string, error){
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string){
	c := &http.Cookie{
		Name: name,
		Value: value,
		MaxAge: int(time.Hour.Seconds()),
		Secure: r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func main() {
	ctx := context.Background()
	var profiles []users

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil{
		log.Fatal(err)
	}
	config := oauth2.Config{
		ClientID: clientID,
		ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("endpoint reached with method: %v\n", r.Method)
		state, err := randString(16)
		if err != nil{
			http.Error(w, "Internal error when generating random string.", http.StatusInternalServerError)
			return
		}
		setCallbackCookie(w, r, "state", state)

		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request){
		log.Printf("endpoint callback reached with method: %v\n", r.Method)
		state, err := r.Cookie("state")
		println(state)
		if err != nil{
			http.Error(w, "state was not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil{
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil{
			http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
		 	UserInfo    *oidc.UserInfo 
		}{oauth2Token, userInfo}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil{
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		profiles = append(profiles, users{
			email: userInfo.Email,
			sub: userInfo.Subject,
		})
		w.Write(data)
	})
	log.Printf("listening on http://%s/", "0.0.0.0:8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
package middleware

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

type contextKey string

const SessionUserKey contextKey = "session_user"

func InitSession(secret string) {
	Store = sessions.NewCookieStore([]byte(secret))
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   false, // localhost dev — no TLS required
	}
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	return Store.Get(r, "restaurant_session")
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := GetSession(r)
		if err != nil || sess.Values["user_id"] == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), SessionUserKey, sess.Values["user_id"])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetSessionUserID(r *http.Request) (int, bool) {
	sess, err := GetSession(r)
	if err != nil || sess.Values["user_id"] == nil {
		return 0, false
	}
	id, ok := sess.Values["user_id"].(int)
	return id, ok
}

package middleware

import (
    "context"
    "database/sql"
    "net/http"
    "strings"

    "myapp/utils"
)

func JWTAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // 1. Extraer el token del header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
                return
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
                http.Error(w, `{"error": "Invalid authorization header format"}`, http.StatusUnauthorized)
                return
            }

            tokenString := parts[1]

            // 2. Verificar el token en la base de datos
            tokenHash := utils.HashToken(tokenString)
            var userID int64
            err := db.QueryRowContext(r.Context(), 
                "SELECT user_id FROM active_tokens WHERE token_hash = ? AND expires_at > datetime('now')",
                tokenHash).Scan(&userID)
            
            if err != nil {
                if err == sql.ErrNoRows {
                    http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusUnauthorized)
                } else {
                    http.Error(w, `{"error": "Error verifying token"}`, http.StatusInternalServerError)
                }
                return
            }

            // 3. Añadir el userID al contexto
            ctx := context.WithValue(r.Context(), "userID", userID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
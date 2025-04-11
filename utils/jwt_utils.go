package utils

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWTSecretKey debe ser configurada desde variables de entorno en producción
var JWTSecretKey = []byte("your-very-secure-secret-key-change-this")

// GenerateJWT crea un nuevo token JWT para un usuario
func GenerateJWT(userID int64) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token válido por 24 horas
	
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTSecretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error firmando token: %w", err)
	}

	return tokenString, expirationTime, nil
}

// HashToken crea un hash seguro del token para almacenamiento
func HashToken(token string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing token: %v", err)
		return ""
	}
	return string(hash)
}

// StoreToken guarda el token en la base de datos
func StoreToken(db *sql.DB, userID int64, tokenString string, expiresAt time.Time) error {
	tokenHash := HashToken(tokenString)
	_, err := db.Exec(
		"INSERT INTO active_tokens(user_id, token_hash, expires_at) VALUES(?, ?, ?)",
		userID, tokenHash, expiresAt,
	)
	return err
}

// InvalidateToken elimina un token de la base de datos (logout)
func InvalidateToken(db *sql.DB, tokenString string) error {
	tokenHash := HashToken(tokenString)
	_, err := db.Exec("DELETE FROM active_tokens WHERE token_hash = ?", tokenHash)
	return err
}

// ValidateToken verifica un token JWT y devuelve el userID si es válido
func ValidateToken(db *sql.DB, tokenString string) (int64, error) {
	// Parsear el token JWT
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return JWTSecretKey, nil
	})

	if err != nil {
		return 0, fmt.Errorf("error parseando token: %w", err)
	}

	if !token.Valid {
		return 0, errors.New("token inválido")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return 0, errors.New("error obteniendo claims del token")
	}

	// Verificar si el token está en la base de datos
	tokenHash := HashToken(tokenString)
	var dbUserID int64
	err = db.QueryRow(
		"SELECT user_id FROM active_tokens WHERE token_hash = ? AND expires_at > datetime('now')",
		tokenHash,
	).Scan(&dbUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("token no encontrado o expirado")
		}
		return 0, fmt.Errorf("error consultando token en DB: %w", err)
	}

	// Convertir subject (userID string) a int64
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error convirtiendo userID: %w", err)
	}

	// Verificar que el userID del token coincide con el de la DB
	if userID != dbUserID {
		return 0, errors.New("discrepancia en userID entre token y DB")
	}

	return userID, nil
}

// JWTAuthMiddleware crea un middleware para autenticación JWT
func JWTAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			userID, err := ValidateToken(db, tokenString)
			if err != nil {
				log.Printf("Error validating token: %v", err)
				http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Añadir userID al contexto
			ctx := context.WithValue(r.Context(), "userID", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CleanupExpiredTokens elimina tokens expirados de la base de datos
func CleanupExpiredTokens(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM active_tokens WHERE expires_at <= datetime('now')")
	return err
}
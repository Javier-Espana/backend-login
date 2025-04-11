package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"myapp/models"
	"myapp/utils"
)

func PostLogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extraer el token del header Authorization
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			respondWithError(w, http.StatusBadRequest, "Invalid authorization header format")
			return
		}
		tokenString := parts[1]

		// 2. Invalidar el token en la base de datos
		err := utils.InvalidateToken(db, tokenString)
		if err != nil {
			log.Printf("Error invalidating token during logout: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Error processing logout")
			return
		}

		// 3. Responder con éxito
		log.Printf("Logout processed for token (hash: %s...)", utils.HashToken(tokenString)[:10])
		respondWithJSON(w, http.StatusOK, models.NewSuccessResponse(map[string]string{"message": "Logout successful"}))
	}
}
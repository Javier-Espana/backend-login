package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"myapp/models"
	"myapp/utils" // Paquete donde estarían generateJWT y storeToken

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Decode Request Body
		var req models.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding login request: %v", err)
			respondWithError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// 2. Basic Validation
		if req.Username == "" || req.Password == "" {
			respondWithError(w, http.StatusBadRequest, "Username and password are required")
			return
		}

		// 3. Query Database for User
		var storedHash string
		var userID int64
		err := db.QueryRowContext(r.Context(),
			"SELECT id, password_hash FROM users WHERE username = ?",
			req.Username,
		).Scan(&userID, &storedHash)

		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			} else {
				log.Printf("Error querying user '%s': %v", req.Username, err)
				respondWithError(w, http.StatusInternalServerError, "Internal server error")
			}
			return
		}

		// 4. Compare Password Hash
		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password))
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}

		// 5. Generate JWT
		tokenString, expirationTime, err := utils.GenerateJWT(userID)
		if err != nil {
			log.Printf("Error generating JWT for user %d: %v", userID, err)
			respondWithError(w, http.StatusInternalServerError, "Error generating session token")
			return
		}

		// 6. Store Token in Database
		err = utils.StoreToken(db, userID, tokenString, expirationTime)
		if err != nil {
			log.Printf("Error storing token for user %d: %v", userID, err)
			respondWithError(w, http.StatusInternalServerError, "Error storing session token")
			return
		}

		log.Printf("Login successful for user ID: %d (%s)", userID, req.Username)

		// 7. Return Success Response with Token
		loginData := models.LoginSuccessData{
			UserID:   userID,
			Username: req.Username,
			Token:    tokenString, // Añadir campo Token en tu modelo LoginSuccessData
		}

		respondWithJSON(w, http.StatusOK, models.NewSuccessResponse(loginData))
		
	}
}
package handlers

import (
    "database/sql"
    "log"
    "net/http"

    "myapp/models"
)

// UserProfileResponse define la estructura para la respuesta del perfil
type UserProfileResponse struct {
    ID       int64  `json:"id"`
    Username string `json:"username"`
    // Puedes añadir más campos aquí según necesites
}

func GetUserProfileHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Obtener userID del contexto (inyectado por el middleware)
        userID, ok := r.Context().Value("userID").(int64)
        if !ok || userID == 0 {
            respondWithError(w, http.StatusInternalServerError, "No se pudo obtener ID de usuario del token")
            return
        }

        // Consultar los datos del perfil
        var profile models.UserProfileResponse
        err := db.QueryRowContext(r.Context(), 
            "SELECT id, username FROM users WHERE id = ?", 
            userID,
        ).Scan(&profile.ID, &profile.Username)

        if err != nil {
            if err == sql.ErrNoRows {
                respondWithError(w, http.StatusNotFound, "Usuario del token no encontrado")
            } else {
                log.Printf("Error consultando perfil para user %d: %v", userID, err)
                respondWithError(w, http.StatusInternalServerError, "Error interno del servidor")
            }
            return
        }

        respondWithJSON(w, http.StatusOK, models.NewSuccessResponse(profile))
    }
}
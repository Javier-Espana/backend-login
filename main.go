package main

import (
	"log"
	"net/http"

	"myapp/handlers"
	"myapp/middleware"

	chiMiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := setupDatabase("./users.db")
	if err != nil {
		log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(configureCORS())

	// --- Rutas Públicas ---
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API de Login v1.0"))
	})

	// Grupo de autenticación
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", handlers.PostRegisterHandler(db))
		r.Post("/login", handlers.PostLoginHandler(db))
	})

	// --- Rutas Protegidas ---
	r.Group(func(r chi.Router) {
		// Middleware JWT para rutas protegidas
		r.Use(middleware.JWTAuthMiddleware(db))

		// Rutas de autenticación protegidas
		r.Post("/auth/logout", handlers.PostLogoutHandler(db))

		// Rutas de usuario protegidas
		r.Get("/users/profile", handlers.GetUserProfileHandler(db))
	})

	// Ruta pública para obtener información básica de usuario
	r.Get("/users/{userID}", handlers.GetUserHandler(db))

	port := ":3000"
	log.Printf("Servidor escuchando en puerto %s", port)
	log.Fatal(http.ListenAndServe(port, r))
}

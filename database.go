package main

import (
    "database/sql"
    "log"

    _ "github.com/mattn/go-sqlite3"
)

type UserModel struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// setupDatabase inicializa la conexión a la BD SQLite
func setupDatabase(dbPath string) (*sql.DB, error) {
    log.Printf("Conectando a la base de datos en: %s", dbPath)
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    if err = db.Ping(); err != nil {
        db.Close()
        return nil, err
    }

    // Crear tabla users si no existe
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    `)
    if err != nil {
        db.Close()
        return nil, err
    }

    log.Println("Base de datos conectada exitosamente.")
    return db, nil
}
package main

import (
	db "github.com/AleBustamante/proyecto_pruebas_unitarias/db"
	api "github.com/AleBustamante/proyecto_pruebas_unitarias/routes"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

// Response es la estructura que devolveremos como JSON
type Response struct {
	Message string `json:"message"`
}

type Product struct {
	ID          int
	Name        string
	Description string
	Price       float32
	Stock       int
	Created_at  int
	Updated_at  int
}

func main() {
	dbService := db.NewDBService()
	api.ExposeAPI(dbService)
}

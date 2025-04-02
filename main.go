package main

import (
	//"net/http"

	//"github.com/gin-gonic/gin"

	api "github.com/AleBustamante/proyecto_final_tecweb/tree/main/backend/routes"
	//"github.com/AleBustamante/proyecto_final_tecweb/tree/main/backend/db"

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

	api.ExposeAPI()

	// Creamos un router de Gin
	//router := gin.Default()

	// Definimos la ruta GET /hola
	//router.GET("/hola", func(c *gin.Context) {
	//response := Response{
	//Message: "¡Hola desde el servidor Go con Gin!",
	//}

	//c.JSON(http.StatusOK, response)
	//})
	//router.POST("/insert", func(c *gin.Context) {
	//response := Response{
	//Message: "This is a confirmation message",
	//}

	//c.JSON(http.StatusOK, response)
	//})

	// Iniciamos el servidor en el puerto 8080
	//router.Run(":8080")
}

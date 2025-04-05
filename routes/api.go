package api

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	db "github.com/AleBustamante/proyecto_pruebas_unitarias/db"
	m "github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(5, 10)

// Middleware para limitar la tasa de peticiones
func rateLimitMiddleware(c *gin.Context) {
	if !limiter.Allow() {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
		c.Abort()
		return
	}
	c.Next()
}

// Cargar variables de entorno
func loadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}
}

// Configurar el logger de Gin
func setupLogger() {
	if gin.Mode() == gin.ReleaseMode {
		f, err := os.Create("gin.log")
		if err != nil {
			log.Fatal("Could not create log file", err)
		}
		gin.DefaultWriter = io.MultiWriter(f, os.Stdout) // log to file and terminal
	}
}

// Middleware para añadir cabeceras de seguridad
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

// Configurar CORS
func setupCORS() cors.Config {
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{
		"http://localhost:4200",
		"http://localhost:8080",
		"https://alebustamante.github.io",
	}
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{
		"Origin",
		"Content-Type",
		"Content-Length",
		"Accept-Encoding",
		"X-CSRF-Token",
		"Authorization",
	}
	config.ExposeHeaders = []string{"Content-Length"}
	config.AllowCredentials = true
	config.MaxAge = 12 * time.Hour
	return config
}

// Controlador para login
func handleLogin(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login data"})
		return
	}

	user, err := db.ValidateUser(loginData.Username, loginData.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

// Controlador para obtener una película por ID
func handleGetMovie(c *gin.Context) {
	id := c.Param("id")
	movie, err := db.FindMovieById(id)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Movie not found"})
		return
	}
	if err != nil {
		log.Printf("Error finding movie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, movie)
}

// Controlador para buscar películas
func handleSearchMovies(c *gin.Context) {
	title := c.Query("q")
	genre := c.Query("genre")

	if title == "" && genre == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one parameter ('q' or 'genre') is needed"})
		return
	}

	movies, err := db.FindByTitleOrGenre(title, genre)
	if err != nil {
		log.Printf("Error searching movies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, movies)
}

// Controlador para registrar un nuevo usuario
func handleRegister(c *gin.Context) {
	var user m.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := db.InsertNewUser(user)
	if err != nil {
		log.Printf("Error registering user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

// Controlador para obtener la lista de seguimiento
func handleGetWatchlist(c *gin.Context) {
	userID, err := strconv.Atoi(c.Query("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}

	// Opcional: filtrar por watched status
	watchedFilter := c.Query("watched")
	var watched *bool
	if watchedFilter != "" {
		watchedBool, err := strconv.ParseBool(watchedFilter)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid watched filter value"})
			return
		}
		watched = &watchedBool
	}

	watchlist, err := db.GetUserWatchlist(userID, watched)
	if err != nil {
		log.Printf("Error getting watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, watchlist)
}

// Controlador para añadir a la lista de seguimiento
func handleAddToWatchlist(c *gin.Context) {
	userID, err := strconv.Atoi(c.Query("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}
	movieID, err := strconv.Atoi(c.Query("movie_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid movie_id"})
		return
	}
	watched, err := strconv.ParseBool(c.Query("watched"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid watched value"})
		return
	}

	if err := db.AddToWatchlist(userID, movieID, watched); err != nil {
		log.Printf("Error adding to watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Watchlist updated successfully"})
}

// Controlador para actualizar el estado de visto
func handleUpdateWatchedStatus(c *gin.Context) {
	userID, err := strconv.Atoi(c.Query("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}
	movieID, err := strconv.Atoi(c.Query("movie_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid movie_id"})
		return
	}
	watched, err := strconv.ParseBool(c.Query("watched"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid watched value"})
		return
	}

	if err := db.UpdateWatchedStatus(userID, movieID, watched); err != nil {
		log.Printf("Error updating watched status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Watched status updated successfully"})
}

// Controlador para eliminar de la lista de seguimiento
func handleRemoveFromWatchlist(c *gin.Context) {
	userID, err := strconv.Atoi(c.Query("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}
	movieID, err := strconv.Atoi(c.Query("movie_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid movie_id"})
		return
	}

	if err := db.RemoveFromWatchlist(userID, movieID); err != nil {
		log.Printf("Error removing from watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Movie removed from watchlist"})
}

// Controlador para obtener un usuario por ID
func handleGetUser(c *gin.Context) {
	requestedUserID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Verificar que el usuario autenticado solo pueda ver su propia información
	authenticatedUserID := c.GetInt("user_id")
	if requestedUserID != authenticatedUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	user, err := db.GetUserByID(requestedUserID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

// Controlador para actualizar un usuario
func handleUpdateUser(c *gin.Context) {
	requestedUserID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Verificar que el usuario autenticado solo pueda modificar su propia información
	authenticatedUserID := c.GetInt("user_id")
	if requestedUserID != authenticatedUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	var updateData struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
		return
	}

	if err := db.UpdateUser(requestedUserID, updateData.Username, updateData.Email, updateData.Password); err != nil {
		log.Printf("Error updating user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// Controlador para eliminar un usuario
func handleDeleteUser(c *gin.Context) {
	requestedUserID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	authenticatedUserID := c.GetInt("user_id")
	if requestedUserID != authenticatedUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if err := db.DeleteUser(requestedUserID); err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// Configurar rutas públicas
func setupPublicRoutes(router *gin.Engine) {
	router.POST("/login", handleLogin)
	router.GET("/movie/:id", handleGetMovie)
	router.GET("/search", handleSearchMovies)
	router.POST("/register", handleRegister)
}

// Configurar rutas protegidas
func setupProtectedRoutes(router *gin.Engine) {
	protected := router.Group("/")
	protected.Use(authMiddleware())

	// Rutas de watchlist
	protected.GET("/watchlist", handleGetWatchlist)
	protected.POST("/watchlist", handleAddToWatchlist)
	protected.PATCH("/watchlist", handleUpdateWatchedStatus)
	protected.DELETE("/watchlist", handleRemoveFromWatchlist)

	// Rutas de usuario
	protected.GET("/user/:id", handleGetUser)
	protected.PATCH("/user/:id", handleUpdateUser)
	protected.DELETE("/user/:id", handleDeleteUser)
}

// Configurar y devolver un router de Gin
func SetupRouter() *gin.Engine {
	// Configuración básica del router
	gin.SetMode(gin.ReleaseMode)
	setupLogger()

	router := gin.Default()
	router.Use(securityHeadersMiddleware())
	router.Use(cors.New(setupCORS()))

	// Configurar rutas
	setupPublicRoutes(router)
	setupProtectedRoutes(router)

	return router
}

// Generar token JWT
func generateToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// Middleware para autenticación JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user_id", int(claims["user_id"].(float64)))
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
		}
	}
}

// Función principal que expone la API
func ExposeAPI() {
	loadEnv()

	router := SetupRouter()

	// Configurar el servidor HTTP
	port := "8080" // Puerto para desarrollo local
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Iniciar el servidor en una goroutine
	go func() {
		log.Printf("Server starting on port %s...\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to initialize server: %v\n", err)
		}
	}()

	// Manejar señales de interrupción para un apagado graceful
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}

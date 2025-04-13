package api

import (
	"context"
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

	m "github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// DBService define la interfaz para las operaciones de base de datos
type DBService interface {
	// Usuarios
	ValidateUser(username, password string) (m.User, error)
	InsertNewUser(user m.User) (m.User, error)
	GetUserByID(userID int) (m.User, error)
	UpdateUser(userID int, username, email, password string) error
	DeleteUser(userID int) error

	// Películas
	FindMovieById(id string) (m.Movie, error)
	FindByTitleOrGenre(title, genre string) ([]m.Movie, error)

	// Watchlist
	GetUserWatchlist(userID int, watchedFilter *bool) ([]m.WatchlistItem, error)
	AddToWatchlist(userID, movieID int, watched bool) error
	UpdateWatchedStatus(userID, movieID int, watched bool) error
	RemoveFromWatchlist(userID, movieID int) error
}

// ConfigService define la interfaz para obtener la configuración
type ConfigService interface {
	GetJWTSecret() string
	GetServerPort() string
	GetAllowedOrigins() []string
}

// DefaultConfigService implementa ConfigService usando variables de entorno
type DefaultConfigService struct {
	jwtSecret      string
	serverPort     string
	allowedOrigins []string
}

// NewDefaultConfigService crea una nueva instancia de DefaultConfigService
func NewDefaultConfigService(jwtSecret, serverPort string, origins []string) *DefaultConfigService {
	return &DefaultConfigService{
		jwtSecret:      jwtSecret,
		serverPort:     serverPort,
		allowedOrigins: origins,
	}
}

// GetJWTSecret devuelve el secreto JWT
func (c *DefaultConfigService) GetJWTSecret() string {
	return c.jwtSecret
}

// GetServerPort devuelve el puerto del servidor
func (c *DefaultConfigService) GetServerPort() string {
	return c.serverPort
}

// GetAllowedOrigins devuelve los orígenes permitidos para CORS
func (c *DefaultConfigService) GetAllowedOrigins() []string {
	return c.allowedOrigins
}

// API estructura principal que contiene las dependencias
type API struct {
	DB     DBService
	Config ConfigService
	Router *gin.Engine
}

// NewAPI crea una nueva instancia de la API
func NewAPI(db DBService, config ConfigService) *API {
	api := &API{
		DB:     db,
		Config: config,
	}
	api.Router = api.setupRouter()
	return api
}

// setupLogger configura el logger de Gin
func setupLogger() {
	if gin.Mode() == gin.ReleaseMode {
		f, err := os.Create("gin.log")
		if err != nil {
			log.Fatal("Could not create log file", err)
		}
		gin.DefaultWriter = io.MultiWriter(f, os.Stdout) // log to file and terminal
	}
}

// securityHeadersMiddleware añade cabeceras de seguridad
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

// setupCORS configura CORS
func (a *API) setupCORS() cors.Config {
	config := cors.DefaultConfig()
	config.AllowOrigins = a.Config.GetAllowedOrigins()
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

// handleLogin maneja el inicio de sesión
func (a *API) handleLogin(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login data"})
		return
	}

	user, err := a.DB.ValidateUser(loginData.Username, loginData.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := a.generateToken(user.ID)
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

// handleGetMovie obtiene una película por ID
func (a *API) handleGetMovie(c *gin.Context) {
	id := c.Param("id")
	movie, err := a.DB.FindMovieById(id)
	if err != nil {
		// Verificar si es un error de "no encontrado"
		if err.Error() == "movie not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Movie not found"})
			return
		}
		log.Printf("Error finding movie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, movie)
}

// handleSearchMovies busca películas
func (a *API) handleSearchMovies(c *gin.Context) {
	title := c.Query("q")
	genre := c.Query("genre")

	if title == "" && genre == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one parameter ('q' or 'genre') is needed"})
		return
	}

	movies, err := a.DB.FindByTitleOrGenre(title, genre)
	if err != nil {
		log.Printf("Error searching movies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, movies)
}

// handleRegister registra un nuevo usuario
func (a *API) handleRegister(c *gin.Context) {
	var user m.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := a.DB.InsertNewUser(user)
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

// handleGetWatchlist obtiene la lista de seguimiento
func (a *API) handleGetWatchlist(c *gin.Context) {
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

	watchlist, err := a.DB.GetUserWatchlist(userID, watched)
	if err != nil {
		log.Printf("Error getting watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, watchlist)
}

// handleAddToWatchlist añade a la lista de seguimiento
func (a *API) handleAddToWatchlist(c *gin.Context) {
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

	if err := a.DB.AddToWatchlist(userID, movieID, watched); err != nil {
		log.Printf("Error adding to watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Watchlist updated successfully"})
}

// handleUpdateWatchedStatus actualiza el estado de visto
func (a *API) handleUpdateWatchedStatus(c *gin.Context) {
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

	if err := a.DB.UpdateWatchedStatus(userID, movieID, watched); err != nil {
		log.Printf("Error updating watched status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Watched status updated successfully"})
}

// handleRemoveFromWatchlist elimina de la lista de seguimiento
func (a *API) handleRemoveFromWatchlist(c *gin.Context) {
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

	if err := a.DB.RemoveFromWatchlist(userID, movieID); err != nil {
		log.Printf("Error removing from watchlist: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Movie removed from watchlist"})
}

// handleGetUser obtiene un usuario por ID
func (a *API) handleGetUser(c *gin.Context) {
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

	user, err := a.DB.GetUserByID(requestedUserID)
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

// handleUpdateUser actualiza un usuario
func (a *API) handleUpdateUser(c *gin.Context) {
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

	if err := a.DB.UpdateUser(requestedUserID, updateData.Username, updateData.Email, updateData.Password); err != nil {
		log.Printf("Error updating user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// handleDeleteUser elimina un usuario
func (a *API) handleDeleteUser(c *gin.Context) {
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

	if err := a.DB.DeleteUser(requestedUserID); err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// setupPublicRoutes configura rutas públicas
func (a *API) setupPublicRoutes(router *gin.Engine) {
	router.POST("/login", a.handleLogin)
	router.GET("/movie/:id", a.handleGetMovie)
	router.GET("/search", a.handleSearchMovies)
	router.POST("/register", a.handleRegister)
}

// setupProtectedRoutes configura rutas protegidas
func (a *API) setupProtectedRoutes(router *gin.Engine) {
	protected := router.Group("/")
	protected.Use(a.authMiddleware())

	// Rutas de watchlist
	protected.GET("/watchlist", a.handleGetWatchlist)
	protected.POST("/watchlist", a.handleAddToWatchlist)
	protected.PATCH("/watchlist", a.handleUpdateWatchedStatus)
	protected.DELETE("/watchlist", a.handleRemoveFromWatchlist)

	// Rutas de usuario
	protected.GET("/user/:id", a.handleGetUser)
	protected.PATCH("/user/:id", a.handleUpdateUser)
	protected.DELETE("/user/:id", a.handleDeleteUser)
}

// setupRouter configura y devuelve un router de Gin
func (a *API) setupRouter() *gin.Engine {
	// Configuración básica del router
	gin.SetMode(gin.ReleaseMode)
	setupLogger()

	router := gin.Default()
	router.Use(securityHeadersMiddleware())
	router.Use(cors.New(a.setupCORS()))

	// Configurar rutas
	a.setupPublicRoutes(router)
	a.setupProtectedRoutes(router)

	return router
}

// generateToken genera un token JWT
func (a *API) generateToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(a.Config.GetJWTSecret()))
}

// authMiddleware middleware para autenticación JWT
func (a *API) authMiddleware() gin.HandlerFunc {
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
			return []byte(a.Config.GetJWTSecret()), nil
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

// Run inicia el servidor HTTP
func (a *API) Run() {
	port := a.Config.GetServerPort()
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      a.Router,
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

// CreateDefaultAPI crea una instancia de API con implementaciones por defecto
func CreateDefaultAPI(dbService DBService, jwtSecret, port string, allowedOrigins []string) *API {
	config := NewDefaultConfigService(jwtSecret, port, allowedOrigins)
	return NewAPI(dbService, config)
}

// ExposeAPI función principal que expone la API
func ExposeAPI(dbService DBService) {
	// Configuración por defecto
	jwtSecret := os.Getenv("JWT_SECRET")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Puerto para desarrollo local
	}

	allowedOrigins := []string{
		"http://localhost:4200",
		"http://localhost:8080",
		"https://alebustamante.github.io",
	}

	api := CreateDefaultAPI(dbService, jwtSecret, port, allowedOrigins)
	api.Run()
}

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

	db "github.com/AleBustamante/proyecto_final_tecweb/tree/main/backend/db"
	m "github.com/AleBustamante/proyecto_final_tecweb/tree/main/backend/models"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(5, 10)

func rateLimitMiddleware(c *gin.Context) {
	if !limiter.Allow() {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
		c.Abort()
		return
	}
	c.Next()
}

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}
}

func ExposeAPI() {
	// Redirect http traffic to https
	go func() {
		log.Println("Starting HTTP to HTTPS redirection server...")
		if err := http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.String()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP Redirection server failed: %v\n", err)
		}
	}()

	loadEnv()
	gin.SetMode(gin.ReleaseMode)

	if gin.Mode() == gin.ReleaseMode {
		f, err := os.Create("gin.log")
		if err != nil {
			log.Fatal("Could not create  log file", err)
		}
		gin.DefaultWriter = io.MultiWriter(f, os.Stdout) //log to file and terminal
	}

	router := gin.Default()

	// Security headers middleware
	router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Next()
	})

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
	router.Use(cors.New(config))

	router.POST("/login", func(c *gin.Context) {
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
	})

	router.GET("/movie/:id", func(c *gin.Context) {
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
	})

	router.GET("/search", func(c *gin.Context) {
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
	})

	router.POST("/register", func(c *gin.Context) {
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
	})

	// Protected routes group
	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/watchlist", func(c *gin.Context) {
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
		})

		protected.POST("/watchlist", func(c *gin.Context) {
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
		})

		protected.PATCH("/watchlist", func(c *gin.Context) {
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
		})

		protected.DELETE("/watchlist", func(c *gin.Context) {
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
		})
		protected.GET("/user/:id", func(c *gin.Context) {
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
		})

		protected.PATCH("/user/:id", func(c *gin.Context) {
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
		})

		protected.DELETE("/user/:id", func(c *gin.Context) {
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
		})
	}
	certFile := "/etc/letsencrypt/live/tecweb-project.duckdns.org/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/tecweb-project.duckdns.org/privkey.pem"

	srv := &http.Server{
		Addr:         ":443",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to initialize server: %v\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")

}

func generateToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

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

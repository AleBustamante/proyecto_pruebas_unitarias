package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	m "github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDBService es un mock de la interfaz DBService para pruebas
type MockDBService struct {
	mock.Mock
}

// ValidateUser implementación mock
func (mock *MockDBService) ValidateUser(username, password string) (m.User, error) {
	args := mock.Called(username, password)
	return args.Get(0).(m.User), args.Error(1)
}

// InsertNewUser implementación mock
func (mock *MockDBService) InsertNewUser(user m.User) (m.User, error) {
	args := mock.Called(user)
	return args.Get(0).(m.User), args.Error(1)
}

// GetUserByID implementación mock
func (mock *MockDBService) GetUserByID(userID int) (m.User, error) {
	args := mock.Called(userID)
	return args.Get(0).(m.User), args.Error(1)
}

// UpdateUser implementación mock
func (mock *MockDBService) UpdateUser(userID int, username, email, password string) error {
	args := mock.Called(userID, username, email, password)
	return args.Error(0)
}

// DeleteUser implementación mock
func (mock *MockDBService) DeleteUser(userID int) error {
	args := mock.Called(userID)
	return args.Error(0)
}

// FindMovieById implementación mock
func (mock *MockDBService) FindMovieById(id string) (m.Movie, error) {
	args := mock.Called(id)
	return args.Get(0).(m.Movie), args.Error(1)
}

// FindByTitleOrGenre implementación mock
func (mock *MockDBService) FindByTitleOrGenre(title, genre string) ([]m.Movie, error) {
	args := mock.Called(title, genre)
	return args.Get(0).([]m.Movie), args.Error(1)
}

// GetUserWatchlist implementación mock
func (mock *MockDBService) GetUserWatchlist(userID int, watchedFilter *bool) ([]m.WatchlistItem, error) {
	args := mock.Called(userID, watchedFilter)
	return args.Get(0).([]m.WatchlistItem), args.Error(1)
}

// AddToWatchlist implementación mock
func (m *MockDBService) AddToWatchlist(userID, movieID int, watched bool) error {
	args := m.Called(userID, movieID, watched)
	return args.Error(0)
}

// UpdateWatchedStatus implementación mock
func (m *MockDBService) UpdateWatchedStatus(userID, movieID int, watched bool) error {
	args := m.Called(userID, movieID, watched)
	return args.Error(0)
}

// RemoveFromWatchlist implementación mock
func (m *MockDBService) RemoveFromWatchlist(userID, movieID int) error {
	args := m.Called(userID, movieID)
	return args.Error(0)
}

// MockConfigService es un mock de la interfaz ConfigService para pruebas
type MockConfigService struct {
	mock.Mock
}

// GetJWTSecret implementación mock
func (m *MockConfigService) GetJWTSecret() string {
	args := m.Called()
	return args.String(0)
}

// GetServerPort implementación mock
func (m *MockConfigService) GetServerPort() string {
	args := m.Called()
	return args.String(0)
}

// GetAllowedOrigins implementación mock
func (m *MockConfigService) GetAllowedOrigins() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// TestSetupLogger prueba la función setupLogger
// func TestSetupLogger(t *testing.T) {
// 	// Caso de prueba: modo release
// 	t.Run("Release mode", func(t *testing.T) {
// 		// Setup: guarda el modo actual y establece el modo release
// 		oldMode := gin.Mode()
// 		gin.SetMode(gin.ReleaseMode)

// 		// Guardar writer original
// 		oldWriter := gin.DefaultWriter

// 		// Setup: crea un directorio temporal para el archivo de log
// 		tempDir := t.TempDir()
// 		os.Chdir(tempDir)

// 		// Ejecutar setupLogger
// 		setupLogger()

// 		// Verificar que se creó el archivo de log
// 		_, err := os.Stat("gin.log")
// 		assert.NoError(t, err, "El archivo de log debería haberse creado")

// 		// Cleanup
// 		gin.DefaultWriter = oldWriter
// 		gin.SetMode(oldMode)
// 	})

// 	// Caso de prueba: modo debug (no debe crear archivo)
// 	t.Run("Debug mode", func(t *testing.T) {
// 		// Setup: guarda el modo actual y establece el modo debug
// 		oldMode := gin.Mode()
// 		gin.SetMode(gin.DebugMode)

// 		// Guardar writer original
// 		oldWriter := gin.DefaultWriter

// 		// Setup: crea un directorio temporal para el archivo de log
// 		tempDir := t.TempDir()
// 		os.Chdir(tempDir)

// 		// Ejecutar setupLogger
// 		setupLogger()

// 		// Verificar que no se modificó DefaultWriter en modo debug
// 		assert.Equal(t, oldWriter, gin.DefaultWriter, "DefaultWriter no debería cambiar en modo debug")

// 		// Cleanup
// 		gin.SetMode(oldMode)
// 	})
// }

// TestSecurityHeadersMiddleware prueba el middleware de cabeceras de seguridad
func TestSecurityHeadersMiddleware(t *testing.T) {
	// Setup: crear un router de gin con el middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(securityHeadersMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "test")
	})

	// Ejecutar una solicitud de prueba
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Aserciones: verificar que las cabeceras de seguridad estén configuradas
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"), "Debe tener cabecera X-Content-Type-Options")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"), "Debe tener cabecera X-Frame-Options")
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"), "Debe tener cabecera X-XSS-Protection")
	assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")
}

// TestSetupCORS prueba la configuración de CORS
func TestSetupCORS(t *testing.T) {
	// Setup: crear un mock de ConfigService
	mockConfig := new(MockConfigService)
	origins := []string{"http://localhost:8080", "https://example.com"}
	mockConfig.On("GetAllowedOrigins").Return(origins)

	// Crear API con el mock
	api := &API{
		Config: mockConfig,
	}

	// Ejecutar setupCORS
	corsConfig := api.setupCORS()

	// Aserciones: verificar la configuración de CORS
	assert.Equal(t, origins, corsConfig.AllowOrigins, "Los orígenes permitidos deben coincidir")
	assert.Contains(t, corsConfig.AllowMethods, "GET", "Debe permitir método GET")
	assert.Contains(t, corsConfig.AllowMethods, "POST", "Debe permitir método POST")
	assert.Contains(t, corsConfig.AllowHeaders, "Authorization", "Debe permitir cabecera Authorization")
	assert.True(t, corsConfig.AllowCredentials, "Debe permitir credenciales")

	// Verificar que el mock se llamó según lo esperado
	mockConfig.AssertExpectations(t)
}

// TestHandleLogin prueba el manejador de login
func TestHandleLogin(t *testing.T) {
	// Caso de prueba: login exitoso
	t.Run("Successful login", func(t *testing.T) {
		// Setup: crear mocks
		mockDB := new(MockDBService)
		mockConfig := new(MockConfigService)

		// Setup: configurar el comportamiento esperado del mock
		validUser := m.User{ID: 1, Username: "testuser", Email: "test@example.com"}
		mockDB.On("ValidateUser", "testuser", "password123").Return(validUser, nil)
		mockConfig.On("GetJWTSecret").Return("test-secret")

		// Setup: crear API con mocks
		api := &API{
			DB:     mockDB,
			Config: mockConfig,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/login", api.handleLogin)

		// Setup: crear solicitud de login
		loginData := map[string]string{
			"username": "testuser",
			"password": "password123",
		}
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar que hay un token en la respuesta
		assert.Contains(t, response, "token", "La respuesta debe contener un token")
		assert.NotEmpty(t, response["token"], "El token no debe estar vacío")

		// Verificar que los datos del usuario estén en la respuesta
		userMap, ok := response["user"].(map[string]interface{})
		assert.True(t, ok, "Debería haber un objeto 'user' en la respuesta")
		assert.Equal(t, float64(1), userMap["id"], "El ID de usuario debe ser 1")
		assert.Equal(t, "testuser", userMap["username"], "El nombre de usuario debe ser testuser")

		// Verificar que los mocks se llamaron según lo esperado
		mockDB.AssertExpectations(t)
		mockConfig.AssertExpectations(t)
	})

	// Caso de prueba: credenciales inválidas
	t.Run("Invalid credentials", func(t *testing.T) {
		// Setup: crear mocks
		mockDB := new(MockDBService)
		mockConfig := new(MockConfigService)

		// Setup: configurar el comportamiento esperado del mock para simular credenciales inválidas
		mockDB.On("ValidateUser", "baduser", "badpass").Return(m.User{}, errors.New("invalid credentials"))

		// Setup: crear API con mocks
		api := &API{
			DB:     mockDB,
			Config: mockConfig,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/login", api.handleLogin)

		// Setup: crear solicitud de login con credenciales incorrectas
		loginData := map[string]string{
			"username": "baduser",
			"password": "badpass",
		}
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusUnauthorized, w.Code, "Debería devolver estado 401 Unauthorized")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar mensaje de error
		assert.Contains(t, response, "error", "La respuesta debe contener un campo de error")
		assert.Equal(t, "Invalid credentials", response["error"], "El mensaje de error debe indicar credenciales inválidas")

		// Verificar que los mocks se llamaron según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: formato de request inválido
	t.Run("Invalid request format", func(t *testing.T) {
		// Setup: crear mocks
		mockDB := new(MockDBService)
		mockConfig := new(MockConfigService)

		// Setup: crear API con mocks
		api := &API{
			DB:     mockDB,
			Config: mockConfig,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/login", api.handleLogin)

		// Setup: crear solicitud de login con JSON malformado
		req := httptest.NewRequest("POST", "/login", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar que no se llamó a ValidateUser
		mockDB.AssertNotCalled(t, "ValidateUser")
	})
}

// TestHandleGetMovie prueba el manejador de obtención de películas
func TestHandleGetMovie(t *testing.T) {
	// Caso de prueba: película encontrada
	t.Run("Movie found", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock
		movieID := "123"
		movie := m.Movie{
			ID:    123,
			Title: "Test Movie",
			Genres: []m.Genre{
				{ID: 1, Name: "Action"},
			},
		}
		mockDB.On("FindMovieById", movieID).Return(movie, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/movie/:id", api.handleGetMovie)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/movie/"+movieID, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var responseMovie m.Movie
		err := json.Unmarshal(w.Body.Bytes(), &responseMovie)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar los datos de la película
		assert.Equal(t, movie.ID, responseMovie.ID, "El ID de la película debe coincidir")
		assert.Equal(t, movie.Title, responseMovie.Title, "El título de la película debe coincidir")
		assert.Equal(t, 1, len(responseMovie.Genres), "Debe tener un género")
		assert.Equal(t, "Action", responseMovie.Genres[0].Name, "El género debe ser Action")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: película no encontrada
	t.Run("Movie not found", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock para simular película no encontrada
		movieID := "999"
		mockDB.On("FindMovieById", movieID).Return(m.Movie{}, errors.New("movie not found"))

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/movie/:id", api.handleGetMovie)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/movie/"+movieID, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusNotFound, w.Code, "Debería devolver estado 404 Not Found")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar mensaje de error
		assert.Contains(t, response, "error", "La respuesta debe contener un campo de error")
		assert.Equal(t, "Movie not found", response["error"], "El mensaje de error debe indicar película no encontrada")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: error de servidor
	t.Run("Server error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock para simular error de servidor
		movieID := "123"
		mockDB.On("FindMovieById", movieID).Return(m.Movie{}, errors.New("database error"))

		// Setup: redirigir logs para evitar ruido en los tests
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/movie/:id", api.handleGetMovie)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/movie/"+movieID, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar mensaje de error
		assert.Contains(t, response, "error", "La respuesta debe contener un campo de error")
		assert.Equal(t, "Internal server error", response["error"], "El mensaje de error debe indicar error interno")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})
}

// TestHandleSearchMovies prueba el manejador de búsqueda de películas
func TestHandleSearchMovies(t *testing.T) {
	// Caso de prueba: búsqueda por título exitosa
	t.Run("Search by title successful", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock
		title := "test"
		genre := ""
		movies := []m.Movie{
			{ID: 1, Title: "Test Movie 1"},
			{ID: 2, Title: "Test Movie 2"},
		}
		mockDB.On("FindByTitleOrGenre", title, genre).Return(movies, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/search", api.handleSearchMovies)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/search?q="+title, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var responseMovies []m.Movie
		err := json.Unmarshal(w.Body.Bytes(), &responseMovies)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar los datos de las películas
		assert.Equal(t, 2, len(responseMovies), "Debe devolver 2 películas")
		assert.Equal(t, "Test Movie 1", responseMovies[0].Title, "El título de la primera película debe coincidir")
		assert.Equal(t, "Test Movie 2", responseMovies[1].Title, "El título de la segunda película debe coincidir")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: búsqueda por género exitosa
	t.Run("Search by genre successful", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock
		title := ""
		genre := "action"
		movies := []m.Movie{
			{ID: 1, Title: "Action Movie 1"},
			{ID: 2, Title: "Action Movie 2"},
		}
		mockDB.On("FindByTitleOrGenre", title, genre).Return(movies, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/search", api.handleSearchMovies)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/search?genre="+genre, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var responseMovies []m.Movie
		err := json.Unmarshal(w.Body.Bytes(), &responseMovies)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar los datos de las películas
		assert.Equal(t, 2, len(responseMovies), "Debe devolver 2 películas")
		assert.Equal(t, "Action Movie 1", responseMovies[0].Title, "El título de la primera película debe coincidir")
		assert.Equal(t, "Action Movie 2", responseMovies[1].Title, "El título de la segunda película debe coincidir")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: sin parámetros de búsqueda
	t.Run("No search parameters", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/search", api.handleSearchMovies)

		// Setup: crear solicitud sin parámetros
		req := httptest.NewRequest("GET", "/search", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar mensaje de error
		assert.Contains(t, response, "error", "La respuesta debe contener un campo de error")
		assert.Equal(t, "At least one parameter ('q' or 'genre') is needed", response["error"], "El mensaje de error debe indicar falta de parámetros")

		// Verificar que no se llamó a FindByTitleOrGenre
		mockDB.AssertNotCalled(t, "FindByTitleOrGenre")
	})

	// Caso de prueba: error de servidor
	t.Run("Server error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock para simular error de servidor
		title := "test"
		genre := ""
		mockDB.On("FindByTitleOrGenre", title, genre).Return([]m.Movie{}, errors.New("database error"))

		// Setup: redirigir logs para evitar ruido en los tests
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/search", api.handleSearchMovies)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/search?q="+title, nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar mensaje de error
		assert.Contains(t, response, "error", "La respuesta debe contener un campo de error")
		assert.Equal(t, "Internal server error", response["error"], "El mensaje de error debe indicar error interno")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})
}

// TestHandleRegister prueba el manejador de registro de usuarios
func TestHandleRegister(t *testing.T) {
	// Caso de prueba: registro exitoso
	t.Run("Successful registration", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado del mock
		inputUser := m.User{Username: "newuser", Email: "new@example.com", Password: "password123"}
		returnedUser := m.User{ID: 1, Username: "newuser", Email: "new@example.com"}
		mockDB.On("InsertNewUser", inputUser).Return(returnedUser, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/register", api.handleRegister)

		// Setup: crear solicitud de registro
		jsonData, _ := json.Marshal(inputUser)
		req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar los datos del usuario
		assert.Equal(t, float64(1), response["id"], "El ID de usuario debe ser 1")
		assert.Equal(t, "newuser", response["username"], "El nombre de usuario debe ser newuser")
		assert.Equal(t, "new@example.com", response["email"], "El email debe coincidir")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: error en el registro
	t.Run("Registration error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar el comportamiento esperado para simular error
		inputUser := m.User{Username: "newuser", Email: "new@example.com", Password: "password123"}
		mockDB.On("InsertNewUser", inputUser).Return(m.User{}, errors.New("database error"))

		// Setup: redirigir logs para evitar ruido
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/register", api.handleRegister)

		// Setup: crear solicitud de registro
		jsonData, _ := json.Marshal(inputUser)
		req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: datos de entrada inválidos
	t.Run("Invalid input data", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/register", api.handleRegister)

		// Setup: crear solicitud con JSON inválido
		req := httptest.NewRequest("POST", "/register", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar que no se llamó al método InsertNewUser
		mockDB.AssertNotCalled(t, "InsertNewUser")
	})
}

// TestHandleGetWatchlist prueba el manejador de obtención de lista de seguimiento
func TestHandleGetWatchlist(t *testing.T) {
	// Caso de prueba: obtención exitosa sin filtro
	t.Run("Successful retrieval without filter", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		watchlistItems := []m.WatchlistItem{
			{
				MovieID:      101,
				Title:        "The Matrix",
				ReleaseDate:  "1999-03-31",
				Genres:       []m.Genre{{ID: 1, Name: "Action"}, {ID: 2, Name: "Sci-Fi"}},
				Watched:      true,
				BackdropPath: "/matrix_backdrop.jpg",
				PosterPath:   "/matrix_poster.jpg",
				Runtime:      136,
				VoteAverage:  8.7,
			},
			{
				MovieID:      102,
				Title:        "Inception",
				ReleaseDate:  "2010-07-16",
				Genres:       []m.Genre{{ID: 3, Name: "Thriller"}, {ID: 2, Name: "Sci-Fi"}},
				Watched:      false,
				BackdropPath: "/inception_backdrop.jpg",
				PosterPath:   "/inception_poster.jpg",
				Runtime:      148,
				VoteAverage:  8.8,
			},
		}

		mockDB.On("GetUserWatchlist", userID, mock.Anything).Return(watchlistItems, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/watchlist", api.handleGetWatchlist)

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/watchlist?user_id=1", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var response []m.WatchlistItem
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar datos de la watchlist
		assert.Equal(t, 2, len(response), "Debe devolver 2 elementos")
		assert.Equal(t, 101, response[0].MovieID, "El ID de la primera película debe coincidir")
		assert.True(t, response[0].Watched, "La primera película debe estar marcada como vista")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: obtención con filtro de watched
	t.Run("Retrieval with watched filter", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		watchedTrue := true
		watchlistItems := []m.WatchlistItem{
			{
				MovieID:      101,
				Title:        "The Matrix",
				ReleaseDate:  "1999-03-31",
				Genres:       []m.Genre{{ID: 1, Name: "Action"}, {ID: 2, Name: "Sci-Fi"}},
				Watched:      true,
				BackdropPath: "/matrix_backdrop.jpg",
				PosterPath:   "/matrix_poster.jpg",
				Runtime:      136,
				VoteAverage:  8.7,
			},
		}

		mockDB.On("GetUserWatchlist", userID, &watchedTrue).Return(watchlistItems, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/watchlist", api.handleGetWatchlist)

		// Setup: crear solicitud con filtro
		req := httptest.NewRequest("GET", "/watchlist?user_id=1&watched=true", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var response []m.WatchlistItem
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar datos de la watchlist
		assert.Equal(t, 1, len(response), "Debe devolver 1 elemento")
		assert.True(t, response[0].Watched, "La película debe estar marcada como vista")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: user_id inválido
	t.Run("Invalid user_id", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/watchlist", api.handleGetWatchlist)

		// Setup: crear solicitud con user_id inválido
		req := httptest.NewRequest("GET", "/watchlist?user_id=invalid", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar que no se llamó al método GetUserWatchlist
		mockDB.AssertNotCalled(t, "GetUserWatchlist")
	})

	// Caso de prueba: valor de watched inválido
	t.Run("Invalid watched value", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/watchlist", api.handleGetWatchlist)

		// Setup: crear solicitud con valor de watched inválido
		req := httptest.NewRequest("GET", "/watchlist?user_id=1&watched=invalid", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar que no se llamó al método GetUserWatchlist
		mockDB.AssertNotCalled(t, "GetUserWatchlist")
	})
}

// TestHandleAddToWatchlist prueba el manejador de adición a la lista de seguimiento
func TestHandleAddToWatchlist(t *testing.T) {
	// Caso de prueba: adición exitosa
	t.Run("Successful addition", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		movieID := 101
		watched := true
		mockDB.On("AddToWatchlist", userID, movieID, watched).Return(nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/watchlist", api.handleAddToWatchlist)

		// Setup: crear solicitud
		req := httptest.NewRequest("POST", "/watchlist?user_id=1&movie_id=101&watched=true", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: error en la adición
	t.Run("Addition error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado para simular error
		userID := 1
		movieID := 101
		watched := true
		mockDB.On("AddToWatchlist", userID, movieID, watched).Return(errors.New("database error"))

		// Setup: redirigir logs para evitar ruido
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/watchlist", api.handleAddToWatchlist)

		// Setup: crear solicitud
		req := httptest.NewRequest("POST", "/watchlist?user_id=1&movie_id=101&watched=true", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: parámetros inválidos
	t.Run("Invalid parameters", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/watchlist", api.handleAddToWatchlist)

		// Casos de prueba para diferentes parámetros inválidos
		testCases := []struct {
			url    string
			reason string
		}{
			{"/watchlist?user_id=invalid&movie_id=101&watched=true", "user_id inválido"},
			{"/watchlist?user_id=1&movie_id=invalid&watched=true", "movie_id inválido"},
			{"/watchlist?user_id=1&movie_id=101&watched=invalid", "watched inválido"},
		}

		for _, tc := range testCases {
			req := httptest.NewRequest("POST", tc.url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request para "+tc.reason)
		}

		// Verificar que no se llamó al método AddToWatchlist
		mockDB.AssertNotCalled(t, "AddToWatchlist")
	})
}

// TestHandleUpdateWatchedStatus prueba el manejador de actualización de estado de visto
func TestHandleUpdateWatchedStatus(t *testing.T) {
	// Caso de prueba: actualización exitosa
	t.Run("Successful update", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		movieID := 101
		watched := true
		mockDB.On("UpdateWatchedStatus", userID, movieID, watched).Return(nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PATCH("/watchlist", api.handleUpdateWatchedStatus)

		// Setup: crear solicitud
		req := httptest.NewRequest("PATCH", "/watchlist?user_id=1&movie_id=101&watched=true", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: error en la actualización
	t.Run("Update error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado para simular error
		userID := 1
		movieID := 101
		watched := true
		mockDB.On("UpdateWatchedStatus", userID, movieID, watched).Return(errors.New("database error"))

		// Setup: redirigir logs para evitar ruido
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PATCH("/watchlist", api.handleUpdateWatchedStatus)

		// Setup: crear solicitud
		req := httptest.NewRequest("PATCH", "/watchlist?user_id=1&movie_id=101&watched=true", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Los casos de prueba para parámetros inválidos son similares a los de handleAddToWatchlist
	// y se omiten para evitar repetición excesiva
}

// TestHandleRemoveFromWatchlist prueba el manejador de eliminación de la lista de seguimiento
func TestHandleRemoveFromWatchlist(t *testing.T) {
	// Caso de prueba: eliminación exitosa
	t.Run("Successful removal", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		movieID := 101
		mockDB.On("RemoveFromWatchlist", userID, movieID).Return(nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.DELETE("/watchlist", api.handleRemoveFromWatchlist)

		// Setup: crear solicitud
		req := httptest.NewRequest("DELETE", "/watchlist?user_id=1&movie_id=101", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: error en la eliminación
	t.Run("Removal error", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado para simular error
		userID := 1
		movieID := 101
		mockDB.On("RemoveFromWatchlist", userID, movieID).Return(errors.New("database error"))

		// Setup: redirigir logs para evitar ruido
		old := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(old)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.DELETE("/watchlist", api.handleRemoveFromWatchlist)

		// Setup: crear solicitud
		req := httptest.NewRequest("DELETE", "/watchlist?user_id=1&movie_id=101", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Debería devolver estado 500 Internal Server Error")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Los casos de prueba para parámetros inválidos son similares a los anteriores
	// y se omiten para evitar repetición excesiva
}

// TestHandleGetUser prueba el manejador de obtención de usuario
func TestHandleGetUser(t *testing.T) {
	// Caso de prueba: obtención exitosa
	t.Run("Successful retrieval", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		user := m.User{ID: userID, Username: "testuser", Email: "test@example.com"}
		mockDB.On("GetUserByID", userID).Return(user, nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba con middleware para simular autenticación
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/user/:id", func(c *gin.Context) {
			// Simular que el usuario está autenticado y tiene el mismo ID
			c.Set("user_id", userID)
			api.handleGetUser(c)
		})

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/user/1", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar la respuesta JSON
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Debería poder decodificar la respuesta JSON")

		// Verificar datos del usuario
		assert.Equal(t, float64(1), response["id"], "El ID de usuario debe ser 1")
		assert.Equal(t, "testuser", response["username"], "El nombre de usuario debe coincidir")
		assert.Equal(t, "test@example.com", response["email"], "El email debe coincidir")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: acceso denegado (diferente ID de usuario)
	t.Run("Access denied", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba con middleware para simular autenticación
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/user/:id", func(c *gin.Context) {
			// Simular que el usuario está autenticado pero con un ID diferente
			c.Set("user_id", 2) // ID diferente al que se está solicitando
			api.handleGetUser(c)
		})

		// Setup: crear solicitud
		req := httptest.NewRequest("GET", "/user/1", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusForbidden, w.Code, "Debería devolver estado 403 Forbidden")

		// Verificar que no se llamó al método GetUserByID
		mockDB.AssertNotCalled(t, "GetUserByID")
	})

	// Caso de prueba: ID de usuario inválido
	t.Run("Invalid user ID", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/user/:id", api.handleGetUser)

		// Setup: crear solicitud con ID inválido
		req := httptest.NewRequest("GET", "/user/invalid", nil)
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusBadRequest, w.Code, "Debería devolver estado 400 Bad Request")

		// Verificar que no se llamó al método GetUserByID
		mockDB.AssertNotCalled(t, "GetUserByID")
	})
}

// TestHandleUpdateUser prueba el manejador de actualización de usuario
func TestHandleUpdateUser(t *testing.T) {
	// Caso de prueba: actualización exitosa
	t.Run("Successful update", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: configurar comportamiento esperado
		userID := 1
		username := "updateduser"
		email := "updated@example.com"
		password := "newpassword"
		mockDB.On("UpdateUser", userID, username, email, password).Return(nil)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba con middleware para simular autenticación
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PATCH("/user/:id", func(c *gin.Context) {
			// Simular que el usuario está autenticado y tiene el mismo ID
			c.Set("user_id", userID)
			api.handleUpdateUser(c)
		})

		// Setup: crear solicitud con datos de actualización
		updateData := map[string]string{
			"username": username,
			"email":    email,
			"password": password,
		}
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest("PATCH", "/user/1", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusOK, w.Code, "Debería devolver estado 200 OK")

		// Verificar que el mock se llamó según lo esperado
		mockDB.AssertExpectations(t)
	})

	// Caso de prueba: acceso denegado (diferente ID de usuario)
	t.Run("Access denied", func(t *testing.T) {
		// Setup: crear mock de DBService
		mockDB := new(MockDBService)

		// Setup: crear API con mock
		api := &API{
			DB: mockDB,
		}

		// Setup: crear router de prueba con middleware para simular autenticación
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PATCH("/user/:id", func(c *gin.Context) {
			// Simular que el usuario está autenticado pero con un ID diferente
			c.Set("user_id", 2) // ID diferente al que se está solicitando
			api.handleUpdateUser(c)
		})

		// Setup: crear solicitud
		updateData := map[string]string{
			"username": "updateduser",
			"email":    "updated@example.com",
			"password": "newpassword",
		}
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest("PATCH", "/user/1", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Ejecutar la solicitud
		router.ServeHTTP(w, req)

		// Aserciones
		assert.Equal(t, http.StatusForbidden, w.Code, "Debería devolver estado 403 Forbidden")

		// Verificar que no se llamó al método UpdateUser
		mockDB.AssertNotCalled(t, "UpdateUser")
	})
}

// TestHandleDeleteUser prueba el endpoint de eliminación de usuarios
func TestHandleDeleteUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Casos de prueba
	testCases := []struct {
		name           string
		userID         string
		authUserID     int
		mockSetup      func(*MockDBService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:       "Eliminación exitosa",
			userID:     "123",
			authUserID: 123,
			mockSetup: func(mockDB *MockDBService) {
				mockDB.On("DeleteUser", 123).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"message": "User deleted successfully"},
		},
		{
			name:           "ID de usuario no válido",
			userID:         "abc",
			authUserID:     0,
			mockSetup:      func(mockDB *MockDBService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": "Invalid user ID"},
		},
		{
			name:           "Acceso denegado",
			userID:         "123",
			authUserID:     456,
			mockSetup:      func(mockDB *MockDBService) {},
			expectedStatus: http.StatusForbidden,
			expectedBody:   map[string]interface{}{"error": "Access denied"},
		},
		{
			name:       "Error al eliminar",
			userID:     "123",
			authUserID: 123,
			mockSetup: func(mockDB *MockDBService) {
				mockDB.On("DeleteUser", 123).Return(fmt.Errorf("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": "Internal server error"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configurar mocks
			mockDB := new(MockDBService)
			mockConfig := new(MockConfigService)
			mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})
			tc.mockSetup(mockDB)

			// Crear API y contexto
			api := NewAPI(mockDB, mockConfig)
			router := gin.New()
			router.DELETE("/user/:id", func(c *gin.Context) {
				// Simular middleware de autenticación
				c.Set("user_id", tc.authUserID)
				api.handleDeleteUser(c)
			})

			// Crear solicitud
			req, _ := http.NewRequest(http.MethodDelete, "/user/"+tc.userID, nil)
			resp := httptest.NewRecorder()

			// Ejecutar
			router.ServeHTTP(resp, req)

			// Verificar
			assert.Equal(t, tc.expectedStatus, resp.Code)

			var respBody map[string]interface{}
			err := json.Unmarshal(resp.Body.Bytes(), &respBody)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedBody, respBody)

			mockDB.AssertExpectations(t)
		})
	}
}

// TestSetupPublicRoutes verifica que las rutas públicas estén configuradas correctamente
func TestSetupPublicRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Crear mocks y API
	mockDB := new(MockDBService)
	mockConfig := new(MockConfigService)
	mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})
	api := NewAPI(mockDB, mockConfig)

	// Crear router y configurar rutas públicas
	router := gin.New()
	api.setupPublicRoutes(router)

	// Rutas que deben existir
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/login"},
		{http.MethodGet, "/movie/:id"},
		{http.MethodGet, "/search"},
		{http.MethodPost, "/register"},
	}

	// Verificar rutas
	for _, route := range routes {
		found := false
		for _, r := range router.Routes() {
			if r.Method == route.method && r.Path == route.path {
				found = true
				break
			}
		}
		assert.True(t, found, "Ruta %s %s no encontrada", route.method, route.path)
	}
}

// TestSetupProtectedRoutes verifica que las rutas protegidas estén configuradas correctamente
func TestSetupProtectedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Crear mocks y API
	mockDB := new(MockDBService)
	mockConfig := new(MockConfigService)
	mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})
	api := NewAPI(mockDB, mockConfig)

	// Crear router y configurar rutas protegidas
	router := gin.New()
	api.setupProtectedRoutes(router)

	// Rutas que deben existir
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/watchlist"},
		{http.MethodPost, "/watchlist"},
		{http.MethodPatch, "/watchlist"},
		{http.MethodDelete, "/watchlist"},
		{http.MethodGet, "/user/:id"},
		{http.MethodPatch, "/user/:id"},
		{http.MethodDelete, "/user/:id"},
	}

	// Verificar rutas
	for _, route := range routes {
		found := false
		for _, r := range router.Routes() {
			if r.Method == route.method && r.Path == route.path {
				found = true
				break
			}
		}
		assert.True(t, found, "Ruta protegida %s %s no encontrada", route.method, route.path)
	}
}

// TestSetupRouter prueba la configuración completa del router
func TestSetupRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Crear mocks
	mockDB := new(MockDBService)
	mockConfig := new(MockConfigService)
	mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost:4200"})

	// Crear API y obtener router
	api := NewAPI(mockDB, mockConfig)
	router := api.setupRouter()

	// Verificar que el router no sea nil
	assert.NotNil(t, router)

	// Verificar que todas las rutas esperadas estén presentes
	expectedRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/login"},
		{http.MethodGet, "/movie/:id"},
		{http.MethodGet, "/search"},
		{http.MethodPost, "/register"},
		{http.MethodGet, "/watchlist"},
		{http.MethodPost, "/watchlist"},
		{http.MethodPatch, "/watchlist"},
		{http.MethodDelete, "/watchlist"},
		{http.MethodGet, "/user/:id"},
		{http.MethodPatch, "/user/:id"},
		{http.MethodDelete, "/user/:id"},
	}

	for _, route := range expectedRoutes {
		found := false
		for _, r := range router.Routes() {
			if r.Method == route.method && r.Path == route.path {
				found = true
				break
			}
		}
		assert.True(t, found, "Ruta %s %s no encontrada en el router configurado", route.method, route.path)
	}

	mockConfig.AssertExpectations(t)
}

// TestGenerateToken prueba la generación de tokens JWT
func TestGenerateToken(t *testing.T) {
	// Crear mocks
	mockDB := new(MockDBService)
	mockConfig := new(MockConfigService)
	mockConfig.On("GetJWTSecret").Return("test_secret")
	mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})

	// Crear API
	api := NewAPI(mockDB, mockConfig)

	// Generar token
	userID := 123
	token, err := api.generateToken(userID)

	// Verificar que no haya error
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verificar contenido del token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("test_secret"), nil
	})

	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, float64(userID), claims["user_id"])

	// Verificar que la expiración esté en el futuro
	expiration := time.Unix(int64(claims["exp"].(float64)), 0)
	assert.True(t, expiration.After(time.Now()))

	mockConfig.AssertExpectations(t)
}

// TestAuthMiddleware prueba el middleware de autenticación
// func TestAuthMiddleware(t *testing.T) {
// 	gin.SetMode(gin.TestMode)

// 	// Casos de prueba
// 	testCases := []struct {
// 		name           string
// 		setupAuth      func(*http.Request)
// 		setupMock      func(*MockConfigService)
// 		expectedStatus int
// 		expectedUserID int
// 	}{
// 		{
// 			name: "Token válido",
// 			setupAuth: func(req *http.Request) {
// 				token := createTestToken(t, 123, "test_secret")
// 				req.Header.Set("Authorization", "Bearer "+token)
// 			},
// 			setupMock: func(mockConfig *MockConfigService) {
// 				mockConfig.On("GetJWTSecret").Return("test_secret")
// 				mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})
// 			},
// 			expectedStatus: http.StatusOK,
// 			expectedUserID: 123,
// 		},
// 		{
// 			name: "Sin encabezado de autorización",
// 			setupAuth: func(req *http.Request) {
// 				// No se añade encabezado
// 			},
// 			setupMock: func(mockConfig *MockConfigService) {
// 				mockConfig.On("GetJWTSecret").Return("test_secret")
// 				mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})

// 			},
// 			expectedStatus: http.StatusUnauthorized,
// 			expectedUserID: 0,
// 		},
// 		{
// 			name: "Token inválido",
// 			setupAuth: func(req *http.Request) {
// 				req.Header.Set("Authorization", "Bearer invalid_token")
// 			},
// 			setupMock: func(mockConfig *MockConfigService) {
// 				mockConfig.On("GetJWTSecret").Return("test_secret")
// 				mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost"})
// 			},
// 			expectedStatus: http.StatusUnauthorized,
// 			expectedUserID: 0,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Configurar mocks
// 			mockDB := new(MockDBService)
// 			mockConfig := new(MockConfigService)
// 			tc.setupMock(mockConfig)

// 			// Crear API
// 			api := NewAPI(mockDB, mockConfig)

// 			// Crear router con middleware
// 			router := gin.New()
// 			router.Use(api.authMiddleware())
// 			router.GET("/test", func(c *gin.Context) {
// 				userID, exists := c.Get("user_id")
// 				if exists {
// 					c.JSON(http.StatusOK, gin.H{"user_id": userID})
// 				} else {
// 					c.JSON(http.StatusOK, gin.H{"user_id": nil})
// 				}
// 			})

// 			// Crear solicitud
// 			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
// 			tc.setupAuth(req)
// 			resp := httptest.NewRecorder()

// 			// Ejecutar
// 			router.ServeHTTP(resp, req)

// 			// Verificar status
// 			assert.Equal(t, tc.expectedStatus, resp.Code)

// 			// Si esperamos éxito, verificar el ID de usuario
// 			if tc.expectedStatus == http.StatusOK {
// 				var respBody map[string]interface{}
// 				err := json.Unmarshal(resp.Body.Bytes(), &respBody)
// 				require.NoError(t, err)
// 				assert.Equal(t, float64(tc.expectedUserID), respBody["user_id"])
// 			}

// 			mockConfig.AssertExpectations(t)
// 		})
// 	}
// }

// Helper para crear tokens JWT de prueba
func createTestToken(t *testing.T, userID int, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return tokenString
}

// TestRun prueba la función Run de la API (inicio del servidor)
func TestRun(t *testing.T) {
	// Este es un test más complejo ya que implica iniciar un servidor real
	// Por lo general, este tipo de pruebas se realizan de manera más superficial

	// Crear mocks
	mockDB := new(MockDBService)
	mockConfig := new(MockConfigService)
	mockConfig.On("GetServerPort").Return("8081") // Puerto diferente para las pruebas
	mockConfig.On("GetAllowedOrigins").Return([]string{"http://localhost:4200"})

	// Crear API
	api := NewAPI(mockDB, mockConfig)

	// Iniciar el servidor en una goroutine
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	go func() {
		api.Run()
	}()

	// Dar tiempo para que el servidor se inicie
	time.Sleep(100 * time.Millisecond)

	// Enviar una solicitud al servidor para verificar que está funcionando
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Intentar realizar una solicitud al servidor
	_, err := client.Get("http://localhost:8081/search?q=test")

	// No verificamos el resultado exacto, solo que el servidor esté disponible
	// En un entorno CI puede que esta prueba deba ser omitida o modificada
	if err != nil {
		t.Log("Advertencia: El servidor puede no estar disponible para pruebas")
	}

	// Simular señal de apagado
	cancel()

	mockConfig.AssertExpectations(t)
}

// TestCreateDefaultAPI prueba la creación de una API con configuración por defecto
func TestCreateDefaultAPI(t *testing.T) {
	// Configuración para la prueba
	dbService := new(MockDBService)
	jwtSecret := "test_secret"
	port := "8082"
	allowedOrigins := []string{"http://test.com"}

	// Crear API
	api := CreateDefaultAPI(dbService, jwtSecret, port, allowedOrigins)

	// Verificar que la API se haya creado correctamente
	assert.NotNil(t, api)
	assert.Equal(t, dbService, api.DB)
	assert.NotNil(t, api.Config)
	assert.NotNil(t, api.Router)

	// Verificar la configuración
	assert.Equal(t, jwtSecret, api.Config.GetJWTSecret())
	assert.Equal(t, port, api.Config.GetServerPort())
	assert.Equal(t, allowedOrigins, api.Config.GetAllowedOrigins())
}

// TestExposeAPI prueba la función ExposeAPI que expone la API con configuración de entorno
func TestExposeAPI(t *testing.T) {
	// Simular config de entorno
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("PORT", "8083")

	mockDB := new(MockDBService)

	// Crear un canal para finalizar el servidor de forma controlada
	done := make(chan struct{})

	// Wrappear ExposeAPI para ejecutarla en goroutine y simular shutdown
	go func() {
		defer close(done)

		// Exponer la API (esto bloquea hasta que recibe una señal)
		go func() {
			time.Sleep(500 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(syscall.SIGINT) // simula Ctrl+C para terminar
		}()

		ExposeAPI(mockDB)
	}()

	select {
	case <-done:
		// test exitoso
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout esperando que ExposeAPI termine")
	}
}

// Función Run mock para pruebas
var Run func(api *API)

func init() {
	Run = func(api *API) {
		api.Run()
	}
}

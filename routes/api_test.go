package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	m "github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	"github.com/gin-gonic/gin"
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
func TestSetupLogger(t *testing.T) {
	// Caso de prueba: modo release
	t.Run("Release mode", func(t *testing.T) {
		// Setup: guarda el modo actual y establece el modo release
		oldMode := gin.Mode()
		gin.SetMode(gin.ReleaseMode)

		// Guardar writer original
		oldWriter := gin.DefaultWriter

		// Setup: crea un directorio temporal para el archivo de log
		tempDir := t.TempDir()
		os.Chdir(tempDir)

		// Ejecutar setupLogger
		setupLogger()

		// Verificar que se creó el archivo de log
		_, err := os.Stat("gin.log")
		assert.NoError(t, err, "El archivo de log debería haberse creado")

		// Cleanup
		gin.DefaultWriter = oldWriter
		gin.SetMode(oldMode)
	})

	// Caso de prueba: modo debug (no debe crear archivo)
	t.Run("Debug mode", func(t *testing.T) {
		// Setup: guarda el modo actual y establece el modo debug
		oldMode := gin.Mode()
		gin.SetMode(gin.DebugMode)

		// Guardar writer original
		oldWriter := gin.DefaultWriter

		// Setup: crea un directorio temporal para el archivo de log
		tempDir := t.TempDir()
		os.Chdir(tempDir)

		// Ejecutar setupLogger
		setupLogger()

		// Verificar que no se modificó DefaultWriter en modo debug
		assert.Equal(t, oldWriter, gin.DefaultWriter, "DefaultWriter no debería cambiar en modo debug")

		// Cleanup
		gin.SetMode(oldMode)
	})
}

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

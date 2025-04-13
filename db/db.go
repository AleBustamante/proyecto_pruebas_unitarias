package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	m "github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	"github.com/joho/godotenv"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

// DBServiceImpl implementa la interfaz DBService
type DBServiceImpl struct {
	// Configuración adicional si es necesaria
	dbURL string // URL de conexión a la base de datos
}

// NewDBService crea una nueva instancia de DBServiceImpl usando variables de entorno
func NewDBService() *DBServiceImpl {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file: %v", err)
		// Continuar de todos modos, pueden existir variables de entorno
	}
	db_name := os.Getenv("TURSO_DB_NAME")
	db_token := os.Getenv("TURSO_AUTH_TOKEN")
	url := "libsql://" + db_name + ".turso.io?authToken=" + db_token

	return &DBServiceImpl{
		dbURL: url,
	}
}

// NewDBServiceWithURL crea una nueva instancia de DBServiceImpl con una URL específica
// Esto facilitará las pruebas al permitir inyectar una URL de prueba
func NewDBServiceWithURL(url string) *DBServiceImpl {
	return &DBServiceImpl{
		dbURL: url,
	}
}

// getDBConnection obtiene una conexión a la base de datos
func (s *DBServiceImpl) getDBConnection() (*sql.DB, error) {
	db, err := sql.Open("libsql", s.dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open db %s: %s", s.dbURL, err)
	}
	return db, nil
}

// ValidateUser valida un usuario
func (s *DBServiceImpl) ValidateUser(username, password string) (m.User, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return m.User{}, err
	}
	defer db.Close()

	var user m.User
	query := `SELECT id, username, email, password FROM users WHERE username = ?`

	err = db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err == sql.ErrNoRows {
		return m.User{}, errors.New("invalid credentials")
	}
	if err != nil {
		return m.User{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return m.User{}, errors.New("invalid credentials")
	}
	// No devolver la contraseña en la respuesta
	user.Password = ""

	return user, nil
}

// InsertNewUser inserta un nuevo usuario
func (s *DBServiceImpl) InsertNewUser(user m.User) (m.User, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return m.User{}, err
	}
	defer db.Close()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return m.User{}, err
	}

	query := `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`
	result, err := db.Exec(query, user.Username, user.Email, hashedPassword)
	if err != nil {
		return m.User{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return m.User{}, err
	}

	user.ID = int(id)
	user.Password = "" // No devolver la contraseña
	return user, nil
}

// FindMovieById encuentra una película por su ID
func (s *DBServiceImpl) FindMovieById(id string) (m.Movie, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return m.Movie{}, err
	}
	defer db.Close()

	movie := m.Movie{}
	query := `
        SELECT m.*, GROUP_CONCAT(g.id) as genre_ids, GROUP_CONCAT(g.name) as genre_names
        FROM movies m
        LEFT JOIN movie_genres mg ON m.id = mg.movie_id
        LEFT JOIN genres g ON mg.genre_id = g.id
        WHERE m.id = ?
        GROUP BY m.id`

	row := db.QueryRow(query, id)
	var genreIDs, genreNames sql.NullString
	err = row.Scan(
		&movie.ID, &movie.ImdbID, &movie.Title, &movie.OriginalTitle,
		&movie.Overview, &movie.Tagline, &movie.BackdropPath, &movie.PosterPath,
		&movie.Budget, &movie.Revenue, &movie.Runtime, &movie.ReleaseDate,
		&movie.OriginalLanguage, &movie.VoteAverage, &movie.VoteCount,
		&movie.Popularity, &movie.Status, &movie.CollectionID,
		&genreIDs, &genreNames,
	)
	if err == sql.ErrNoRows {
		return movie, errors.New("movie not found")
	}
	if err != nil {
		return movie, err
	}

	// Initialize empty genres slice
	movie.Genres = []m.Genre{}

	// Parse genres if they exist
	if genreIDs.Valid && genreNames.Valid {
		movie.Genres = parseGenres(genreIDs, genreNames)
	}
	return movie, nil
}

// FindByTitleOrGenre busca películas por título o género
func (s *DBServiceImpl) FindByTitleOrGenre(title, genre string) ([]m.Movie, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
        SELECT DISTINCT m.*, GROUP_CONCAT(g.id) as genre_ids, GROUP_CONCAT(g.name) as genre_names
        FROM movies m
        LEFT JOIN movie_genres mg ON m.id = mg.movie_id
        LEFT JOIN genres g ON mg.genre_id = g.id
        WHERE 1=1`
	args := []interface{}{}

	if title != "" {
		query += ` AND LOWER(m.title) LIKE LOWER(?)`
		args = append(args, "%"+title+"%")
	}
	if genre != "" {
		query += ` AND EXISTS (
            SELECT 1 FROM movie_genres mg2
            JOIN genres g2 ON mg2.genre_id = g2.id
            WHERE mg2.movie_id = m.id AND LOWER(g2.name) LIKE LOWER(?)
        )`
		args = append(args, "%"+genre+"%")
	}
	query += ` GROUP BY m.id ORDER BY m.title`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var movies []m.Movie
	for rows.Next() {
		var movie m.Movie
		var genreIDs, genreNames sql.NullString
		err = rows.Scan(
			&movie.ID, &movie.ImdbID, &movie.Title, &movie.OriginalTitle,
			&movie.Overview, &movie.Tagline, &movie.BackdropPath, &movie.PosterPath,
			&movie.Budget, &movie.Revenue, &movie.Runtime, &movie.ReleaseDate,
			&movie.OriginalLanguage, &movie.VoteAverage, &movie.VoteCount,
			&movie.Popularity, &movie.Status, &movie.CollectionID,
			&genreIDs, &genreNames,
		)
		if err != nil {
			return nil, err
		}

		// Initialize empty genres slice
		movie.Genres = []m.Genre{}

		// Parse genres if they exist
		if genreIDs.Valid && genreNames.Valid {
			movie.Genres = parseGenres(genreIDs, genreNames)
		}
		movies = append(movies, movie)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return movies, nil
}

// GetUserWatchlist obtiene la lista de películas en la watchlist del usuario
func (s *DBServiceImpl) GetUserWatchlist(userID int, watchedFilter *bool) ([]m.WatchlistItem, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return []m.WatchlistItem{}, err
	}
	defer db.Close()

	baseQuery := `
        SELECT m.id, m.title, m.release_date, w.watched,
               m.backdrop_path, m.poster_path, m.runtime, m.vote_average,
               GROUP_CONCAT(g.id) as genre_ids,
               GROUP_CONCAT(g.name) as genre_names
        FROM user_watchlist w
        JOIN movies m ON w.movie_id = m.id
        LEFT JOIN movie_genres mg ON m.id = mg.movie_id
        LEFT JOIN genres g ON mg.genre_id = g.id
        WHERE w.user_id = ?`

	args := []interface{}{userID}
	if watchedFilter != nil {
		baseQuery += " AND w.watched = ?"
		args = append(args, *watchedFilter)
	}
	baseQuery += " GROUP BY m.id ORDER BY m.title"

	rows, err := db.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var watchlist []m.WatchlistItem
	for rows.Next() {
		var item m.WatchlistItem
		var genreIDs, genreNames sql.NullString
		err := rows.Scan(
			&item.MovieID,
			&item.Title,
			&item.ReleaseDate,
			&item.Watched,
			&item.BackdropPath,
			&item.PosterPath,
			&item.Runtime,
			&item.VoteAverage,
			&genreIDs,
			&genreNames,
		)
		if err != nil {
			return nil, err
		}

		if genreIDs.Valid && genreNames.Valid {
			item.Genres = parseGenres(genreIDs, genreNames)
		}
		watchlist = append(watchlist, item)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return watchlist, nil
}

// GetUserByID obtiene información de un usuario por su ID
func (s *DBServiceImpl) GetUserByID(userID int) (m.User, error) {
	db, err := s.getDBConnection()
	if err != nil {
		return m.User{}, err
	}
	defer db.Close()

	var user m.User
	query := `SELECT id, username, email FROM users WHERE id = ?`
	err = db.QueryRow(query, userID).Scan(&user.ID, &user.Username, &user.Email)
	if err == sql.ErrNoRows {
		return m.User{}, errors.New("user not found")
	}
	if err != nil {
		return m.User{}, err
	}

	return user, nil
}

// UpdateUser actualiza la información de un usuario
func (s *DBServiceImpl) UpdateUser(userID int, username, email, password string) error {
	db, err := s.getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	// Construir la consulta dinámicamente basada en los campos proporcionados
	updates := []string{}
	args := []interface{}{}

	if username != "" {
		updates = append(updates, "username = ?")
		args = append(args, username)
	}
	if email != "" {
		updates = append(updates, "email = ?")
		args = append(args, email)
	}
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		updates = append(updates, "password = ?")
		args = append(args, hashedPassword)
	}

	if len(updates) == 0 {
		return errors.New("no fields to update")
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(updates, ", "))
	args = append(args, userID)

	result, err := db.Exec(query, args...)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// DeleteUser elimina un usuario y sus datos asociados
func (s *DBServiceImpl) DeleteUser(userID int) error {
	db, err := s.getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM user_watchlist WHERE user_id = ?", userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		tx.Rollback()
		return err
	}
	if rowsAffected == 0 {
		tx.Rollback()
		return errors.New("user not found")
	}

	return tx.Commit()
}

// AddToWatchlist añade una película a la watchlist del usuario
func (s *DBServiceImpl) AddToWatchlist(userID, movieID int, watched bool) error {
	db, err := s.getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	// Primero verificamos si ya existe en la watchlist
	var exists bool
	err = db.QueryRow("SELECT 1 FROM user_watchlist WHERE user_id = ? AND movie_id = ?", userID, movieID).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return err
	}

	// Si ya existe, actualizamos el estado
	if exists {
		_, err = db.Exec("UPDATE user_watchlist SET watched = ? WHERE user_id = ? AND movie_id = ?", watched, userID, movieID)
	} else {
		// Si no existe, lo insertamos
		_, err = db.Exec("INSERT INTO user_watchlist (user_id, movie_id, watched) VALUES (?, ?, ?)", userID, movieID, watched)
	}

	return err
}

// UpdateWatchedStatus actualiza el estado "watched" de una película en la watchlist
func (s *DBServiceImpl) UpdateWatchedStatus(userID, movieID int, watched bool) error {
	db, err := s.getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	result, err := db.Exec("UPDATE user_watchlist SET watched = ? WHERE user_id = ? AND movie_id = ?", watched, userID, movieID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("movie not found in watchlist")
	}

	return nil
}

// RemoveFromWatchlist elimina una película de la watchlist del usuario
func (s *DBServiceImpl) RemoveFromWatchlist(userID, movieID int) error {
	db, err := s.getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	result, err := db.Exec("DELETE FROM user_watchlist WHERE user_id = ? AND movie_id = ?", userID, movieID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("movie not found in watchlist")
	}

	return nil
}

// Función auxiliar para parsear los géneros desde strings concatenados
func parseGenres(genreIDs, genreNames sql.NullString) []m.Genre {
	if !genreIDs.Valid || !genreNames.Valid {
		return []m.Genre{}
	}

	ids := strings.Split(genreIDs.String, ",")
	names := strings.Split(genreNames.String, ",")

	// Asegurarnos de que las listas tengan la misma longitud
	minLength := len(ids)
	if len(names) < minLength {
		minLength = len(names)
	}

	genres := make([]m.Genre, 0, minLength)
	for i := 0; i < minLength; i++ {
		id, err := strconv.Atoi(ids[i])
		if err != nil {
			continue // Saltamos este género si el ID no es válido
		}
		genres = append(genres, m.Genre{
			ID:   id,
			Name: names[i],
		})
	}
	return genres
}

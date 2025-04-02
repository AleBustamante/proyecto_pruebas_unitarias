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

	m "github.com/AleBustamante/proyecto_final_tecweb/tree/main/backend/models"
	"github.com/joho/godotenv"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

func getDBConnection() (*sql.DB, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	db_name := os.Getenv("TURSO_DB_NAME")
	db_token := os.Getenv("TURSO_AUTH_TOKEN")
	url := "libsql://" + db_name + ".turso.io?authToken=" + db_token

	db, err := sql.Open("libsql", url)
	if err != nil {
		return nil, fmt.Errorf("failed to open db %s: %s", url, err)
	}
	return db, nil
}

func InsertNewUser(user m.User) (m.User, error) {
	db, err := getDBConnection()

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
	return user, nil
}

func FindMovieById(id string) (m.Movie, error) {
	db, err := getDBConnection()
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
	if err == nil && (genreIDs.Valid && genreNames.Valid) {
		movie.Genres = parseGenres(genreIDs, genreNames)
	}
	return movie, nil
}

func FindByTitleOrGenre(title, genre string) ([]m.Movie, error) {
	db, err := getDBConnection()
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
	query += ` GROUP BY m.id`

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
		if err == nil && (genreIDs.Valid && genreNames.Valid) {
			movie.Genres = parseGenres(genreIDs, genreNames)
		}
		movies = append(movies, movie)
	}

	return movies, nil
}

func AddToWatchlist(userID, movieID int, watched bool) error {
	db, err := getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	query := `
        INSERT INTO user_watchlist (user_id, movie_id, watched)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, movie_id) DO UPDATE SET watched = ?`

	_, err = db.Exec(query, userID, movieID, watched, watched)
	return err
}

func parseGenres(genreIDs, genreNames sql.NullString) []m.Genre {
	if !genreIDs.Valid || !genreNames.Valid {
		return []m.Genre{}
	}

	ids := strings.Split(genreIDs.String, ",")
	names := strings.Split(genreNames.String, ",")

	// Asegurarse de que tenemos el mismo número de IDs y nombres
	if len(ids) != len(names) {
		return []m.Genre{}
	}

	genres := make([]m.Genre, len(ids))
	for i := range ids {
		id, err := strconv.Atoi(strings.TrimSpace(ids[i]))
		if err != nil {
			continue
		}
		genres[i] = m.Genre{
			ID:   id,
			Name: strings.TrimSpace(names[i]),
		}
	}

	return genres
}

func UpdateWatchedStatus(userID, movieID int, watched bool) error {
	db, err := getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	query := `UPDATE user_watchlist SET watched = ? WHERE user_id = ? AND movie_id = ?`
	result, err := db.Exec(query, watched, userID, movieID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("no rows updated, check if the user and movie exist in the watchlist")
	}
	return nil
}
func RemoveFromWatchlist(userID, movieID int) error {
	db, err := getDBConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	query := `DELETE FROM user_watchlist WHERE user_id = ? AND movie_id = ?`
	result, err := db.Exec(query, userID, movieID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("no rows deleted, check if the user and movie exist in the watchlist")
	}
	return nil
}

func ValidateUser(username, password string) (m.User, error) {
	db, err := getDBConnection()
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

func GetUserWatchlist(userID int, watchedFilter *bool) ([]m.WatchlistItem, error) {
	db, err := getDBConnection()
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

func GetUserByID(userID int) (m.User, error) {
	db, err := getDBConnection()
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

func UpdateUser(userID int, username, email, password string) error {
	db, err := getDBConnection()
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

func DeleteUser(userID int) error {
	db, err := getDBConnection()
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

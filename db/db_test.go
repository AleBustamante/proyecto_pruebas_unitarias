// db_test.go
package db

import (
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/AleBustamante/proyecto_pruebas_unitarias/models"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for in-memory testing
	"golang.org/x/crypto/bcrypt"
)

// keepAlive keeps the in-memory DB alive across multiple connections.
var keepAlive *sql.DB

// TestMain sets up the in-memory SQLite database by registering it as "libsql"
// and creating the required schema. The DSN "file::memory:?cache=shared" is used
// so that new connections created in each function share the same database.
func TestMain(m *testing.M) {
	// Register the SQLite driver under the name "libsql".
	// This makes every call to sql.Open("libsql", dsn) use the sqlite3 driver.
	// (If you later wish to use sqlmock, you could change this registration.)
	// The DSN here creates an in-memory database with a shared cache.
	var err error
	keepAlive, err = sql.Open("libsql", "file::memory:?cache=shared")
	if err != nil {
		log.Fatalf("failed to open shared database: %v", err)
	}
	// Create the tables your functions require.
	if err := setupSchema(keepAlive); err != nil {
		log.Fatalf("failed to setup schema: %v", err)
	}

	// Run tests.
	code := m.Run()
	keepAlive.Close()
	os.Exit(code)
}

// setupSchema creates minimal tables needed for the tests.
func setupSchema(db *sql.DB) error {
	stmts := []string{
		// Users table for ValidateUser, InsertNewUser, GetUserByID, UpdateUser, DeleteUser.
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT,
			email TEXT,
			password TEXT
		);`,
		// Movies table for FindMovieById and FindByTitleOrGenre.
		`CREATE TABLE IF NOT EXISTS movies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			imdb_id TEXT,
			title TEXT,
			original_title TEXT,
			overview TEXT,
			tagline TEXT,
			backdrop_path TEXT,
			poster_path TEXT,
			budget INTEGER,
			revenue INTEGER,
			runtime INTEGER,
			release_date TEXT,
			original_language TEXT,
			vote_average REAL,
			vote_count INTEGER,
			popularity REAL,
			status TEXT,
			collection_id INTEGER
		);`,
		// Genres table used in movie queries.
		`CREATE TABLE IF NOT EXISTS genres (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT
		);`,
		// Movie-Genres junction table.
		`CREATE TABLE IF NOT EXISTS movie_genres (
			movie_id INTEGER,
			genre_id INTEGER
		);`,
		// User watchlist table for GetUserWatchlist, AddToWatchlist, etc.
		`CREATE TABLE IF NOT EXISTS user_watchlist (
			user_id INTEGER,
			movie_id INTEGER,
			watched BOOLEAN,
			backdrop_path TEXT,
			poster_path TEXT,
			runtime INTEGER,
			vote_average REAL,
			title TEXT,
			release_date TEXT
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// resetDB clears all the tables so that tests start with a clean state.
func resetDB(t *testing.T) {
	t.Helper()
	tables := []string{"users", "movies", "genres", "movie_genres", "user_watchlist"}
	for _, table := range tables {
		if _, err := keepAlive.Exec("DELETE FROM " + table); err != nil {
			t.Fatalf("failed to clear table %s: %v", table, err)
		}
	}
}

// TestNewDBService constructors simply set the dbURL.
func TestNewDBService(t *testing.T) {
	svc := NewDBService()
	if svc.dbURL == "" {
		t.Error("expected non-empty dbURL")
	}
}

func TestNewDBServiceWithURL(t *testing.T) {
	url := "file::memory:?cache=shared"
	svc := NewDBServiceWithURL(url)
	if svc.dbURL != url {
		t.Errorf("expected dbURL to be %s, got %s", url, svc.dbURL)
	}
}

// Test getDBConnection (indirectly used by all functions). We simply try opening a connection.
func TestGetDBConnection(t *testing.T) {
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	dbConn, err := svc.getDBConnection()
	if err != nil {
		t.Fatalf("expected connection, got error: %v", err)
	}
	dbConn.Close()
}

// Test ValidateUser covers:
// - valid credentials,
// - wrong password,
// - user not found.
func TestValidateUser(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a test user in the DB.
	password := "secret"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = keepAlive.Exec(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
		"testuser", "test@example.com", string(hashed))
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	// Case 1: valid credentials.
	user, err := svc.ValidateUser("testuser", "secret")
	if err != nil {
		t.Errorf("expected valid credentials, got error: %v", err)
	}
	if user.Username != "testuser" || user.Email != "test@example.com" {
		t.Errorf("unexpected user returned: %+v", user)
	}
	if user.Password != "" {
		t.Errorf("password field should be empty in result")
	}

	// Case 2: wrong password.
	_, err = svc.ValidateUser("testuser", "wrong")
	if err == nil || !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("expected invalid credentials error, got: %v", err)
	}

	// Case 3: user not found.
	_, err = svc.ValidateUser("nouser", "secret")
	if err == nil || !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("expected invalid credentials error for non-existing user, got: %v", err)
	}
}

// Test InsertNewUser tests creating a new user.
func TestInsertNewUser(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	newUser := models.User{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "newpassword",
	}
	createdUser, err := svc.InsertNewUser(newUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if createdUser.ID <= 0 {
		t.Errorf("expected valid user ID, got %d", createdUser.ID)
	}
	if createdUser.Password != "" {
		t.Errorf("password field should be empty in result")
	}

	// Check that the user was really inserted.
	row := keepAlive.QueryRow(`SELECT username, email FROM users WHERE id = ?`, createdUser.ID)
	var username, email string
	if err := row.Scan(&username, &email); err != nil {
		t.Fatalf("failed to retrieve inserted user: %v", err)
	}
	if username != newUser.Username || email != newUser.Email {
		t.Error("inserted user does not match provided details")
	}
}

// Test FindMovieById covers a movie found and not found.
func TestFindMovieById(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a movie.
	res, err := keepAlive.Exec(`INSERT INTO movies (imdb_id, title, original_title, overview, tagline,
		backdrop_path, poster_path, budget, revenue, runtime, release_date, original_language,
		vote_average, vote_count, popularity, status, collection_id) VALUES 
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tt123", "Test Movie", "Test Movie", "Overview", "Tagline",
		"backdrop.jpg", "poster.jpg", 1000, 5000, 120, "2025-01-01", "en",
		8.5, 100, 10.0, "Released", 0)
	if err != nil {
		t.Fatalf("failed to insert movie: %v", err)
	}
	movieID, _ := res.LastInsertId()
	// Insert genres and link them.
	_, err = keepAlive.Exec(`INSERT INTO genres (id, name) VALUES (1, 'Action'), (2, 'Comedy')`)
	if err != nil {
		t.Fatalf("failed to insert genres: %v", err)
	}
	_, err = keepAlive.Exec(`INSERT INTO movie_genres (movie_id, genre_id) VALUES (?, ?), (?, ?)`, movieID, 1, movieID, 2)
	if err != nil {
		t.Fatalf("failed to link genres: %v", err)
	}

	// Case: movie found.
	movie, err := svc.FindMovieById(strconv.FormatInt(movieID, 10))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if movie.Title != "Test Movie" {
		t.Errorf("expected title 'Test Movie', got %s", movie.Title)
	}
	// Check that genres were parsed.
	if len(movie.Genres) != 2 {
		t.Errorf("expected 2 genres, got %d", len(movie.Genres))
	}

	// Case: movie not found.
	_, err = svc.FindMovieById("9999")
	if err == nil || !strings.Contains(err.Error(), "movie not found") {
		t.Errorf("expected movie not found error, got %v", err)
	}
}

// Test FindByTitleOrGenre tests searching movies.
func TestFindByTitleOrGenre(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert movies.
	_, err := keepAlive.Exec(`INSERT INTO movies (title) VALUES (?)`, "Alpha")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := keepAlive.Exec(`INSERT INTO movies (title) VALUES (?)`, "Beta")
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := res2.LastInsertId()
	// Insert genres.
	_, err = keepAlive.Exec(`INSERT INTO genres (id, name) VALUES (10, 'Drama')`)
	if err != nil {
		t.Fatal(err)
	}
	// Link Beta to Drama.
	_, err = keepAlive.Exec(`INSERT INTO movie_genres (movie_id, genre_id) VALUES (?, ?)`, id2, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Search by title substring.
	movies, err := svc.FindByTitleOrGenre("Alp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(movies) != 1 || movies[0].Title != "Alpha" {
		t.Errorf("expected one movie 'Alpha', got %+v", movies)
	}

	// Search by genre substring.
	movies, err = svc.FindByTitleOrGenre("", "dram")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(movies) != 1 || movies[0].Title != "Beta" {
		t.Errorf("expected one movie 'Beta', got %+v", movies)
	}
}

// Test GetUserWatchlist tests retrieval of a user’s watchlist.
func TestGetUserWatchlist(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a movie.
	_, err := keepAlive.Exec(`INSERT INTO movies (id, title, release_date, backdrop_path, poster_path, runtime, vote_average)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "Movie1", "2025-01-01", "back.jpg", "post.jpg", 100, 8.0)
	if err != nil {
		t.Fatal(err)
	}
	// Insert a watchlist item.
	_, err = keepAlive.Exec(`INSERT INTO user_watchlist (user_id, movie_id, watched, title, release_date, backdrop_path, poster_path, runtime, vote_average)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, 42, 1, false, "Movie1", "2025-01-01", "back.jpg", "post.jpg", 100, 8.0)
	if err != nil {
		t.Fatal(err)
	}
	// Also insert genres for the movie.
	_, err = keepAlive.Exec(`INSERT INTO genres (id, name) VALUES (5, 'Sci-Fi')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = keepAlive.Exec(`INSERT INTO movie_genres (movie_id, genre_id) VALUES (1, 5)`)
	if err != nil {
		t.Fatal(err)
	}

	// Case: without watched filter.
	watchlist, err := svc.GetUserWatchlist(42, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(watchlist) != 1 {
		t.Errorf("expected 1 watchlist item, got %d", len(watchlist))
	}
	// Check parsed genres.
	if len(watchlist[0].Genres) != 1 || watchlist[0].Genres[0].Name != "Sci-Fi" {
		t.Errorf("unexpected genres: %+v", watchlist[0].Genres)
	}

	// Case: with watched filter (no matching items).
	trueVal := true
	watchlist, err = svc.GetUserWatchlist(42, &trueVal)
	if err != nil {
		t.Fatalf("unexpected error with filter: %v", err)
	}
	if len(watchlist) != 0 {
		t.Errorf("expected 0 watchlist items for watched=true, got %d", len(watchlist))
	}
}

// Test GetUserByID tests successful and not found cases.
func TestGetUserByID(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a user.
	res, err := keepAlive.Exec(`INSERT INTO users (username, email) VALUES (?, ?)`, "user1", "user1@example.com")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()

	// Case: user found.
	user, err := svc.GetUserByID(int(uid))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Username != "user1" {
		t.Errorf("expected username 'user1', got %s", user.Username)
	}

	// Case: user not found.
	_, err = svc.GetUserByID(9999)
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Errorf("expected user not found error, got %v", err)
	}
}

// Test UpdateUser tests updating various fields including password hashing.
func TestUpdateUser(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a user with a known password.
	res, err := keepAlive.Exec(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
		"olduser", "old@example.com", "oldpass")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()

	// Case: no fields to update.
	err = svc.UpdateUser(int(uid), "", "", "")
	if err == nil || !strings.Contains(err.Error(), "no fields to update") {
		t.Errorf("expected no fields to update error, got %v", err)
	}

	// Case: update username and email.
	err = svc.UpdateUser(int(uid), "newuser", "new@example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify changes.
	row := keepAlive.QueryRow(`SELECT username, email FROM users WHERE id = ?`, uid)
	var uname, email string
	if err := row.Scan(&uname, &email); err != nil {
		t.Fatal(err)
	}
	if uname != "newuser" || email != "new@example.com" {
		t.Errorf("update did not occur: got %s, %s", uname, email)
	}

	// Case: update password.
	err = svc.UpdateUser(int(uid), "", "", "newpassword")
	if err != nil {
		t.Fatalf("unexpected error updating password: %v", err)
	}
	// Fetch the hashed password directly.
	row = keepAlive.QueryRow(`SELECT password FROM users WHERE id = ?`, uid)
	var hashedPass string
	if err := row.Scan(&hashedPass); err != nil {
		t.Fatal(err)
	}
	// Ensure that the password was hashed and does not equal "newpassword".
	if hashedPass == "newpassword" {
		t.Errorf("password was not hashed")
	}
	// Also verify that bcrypt comparison passes.
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte("newpassword")); err != nil {
		t.Errorf("password hash does not match: %v", err)
	}

	// Case: update non-existent user.
	err = svc.UpdateUser(9999, "x", "x", "x")
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Errorf("expected error for non-existent user, got %v", err)
	}
}

// Test DeleteUser tests deleting a user and rolling back on error (if no user deleted).
func TestDeleteUser(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a user.
	res, err := keepAlive.Exec(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
		"todelete", "del@example.com", "pass")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	// Insert an associated watchlist entry.
	_, err = keepAlive.Exec(`INSERT INTO user_watchlist (user_id, movie_id, watched) VALUES (?, ?, ?)`,
		uid, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	// Case: successful deletion.
	err = svc.DeleteUser(int(uid))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify user deletion.
	row := keepAlive.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, uid)
	var count int
	if err := row.Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected user to be deleted, count=%d", count)
	}

	// Case: deleting non-existing user.
	err = svc.DeleteUser(9999)
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Errorf("expected error for non-existent user deletion, got %v", err)
	}
}

// Test AddToWatchlist tests both update and insert scenarios.
func TestAddToWatchlist(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Prepare: Insert a watchlist row manually for update case.
	_, err := keepAlive.Exec(`INSERT INTO user_watchlist (user_id, movie_id, watched) VALUES (?,?,?)`, 1, 10, false)
	if err != nil {
		t.Fatal(err)
	}

	// Case: update existing watchlist record.
	err = svc.AddToWatchlist(1, 10, true)
	if err != nil {
		t.Fatalf("unexpected error on update: %v", err)
	}
	row := keepAlive.QueryRow(`SELECT watched FROM user_watchlist WHERE user_id = ? AND movie_id = ?`, 1, 10)
	var watched bool
	if err := row.Scan(&watched); err != nil {
		t.Fatal(err)
	}
	if !watched {
		t.Errorf("expected watched=true, got false")
	}

	// Case: insert new watchlist record.
	err = svc.AddToWatchlist(2, 20, false)
	if err != nil {
		t.Fatalf("unexpected error on insert: %v", err)
	}
	row = keepAlive.QueryRow(`SELECT watched FROM user_watchlist WHERE user_id = ? AND movie_id = ?`, 2, 20)
	if err := row.Scan(&watched); err != nil {
		t.Fatal(err)
	}
	if watched {
		t.Errorf("expected watched=false, got true")
	}
}

// Test UpdateWatchedStatus tests successful update and not found scenario.
func TestUpdateWatchedStatus(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a watchlist row.
	_, err := keepAlive.Exec(`INSERT INTO user_watchlist (user_id, movie_id, watched) VALUES (?,?,?)`, 3, 30, false)
	if err != nil {
		t.Fatal(err)
	}
	// Update watched status.
	err = svc.UpdateWatchedStatus(3, 30, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	row := keepAlive.QueryRow(`SELECT watched FROM user_watchlist WHERE user_id = ? AND movie_id = ?`, 3, 30)
	var watched bool
	if err := row.Scan(&watched); err != nil {
		t.Fatal(err)
	}
	if !watched {
		t.Errorf("expected watched=true after update, got false")
	}
	// Try updating a non-existent record.
	err = svc.UpdateWatchedStatus(3, 999, true)
	if err == nil || !strings.Contains(err.Error(), "movie not found in watchlist") {
		t.Errorf("expected error for non-existent record, got %v", err)
	}
}

// Test RemoveFromWatchlist tests removal of a watchlist record.
func TestRemoveFromWatchlist(t *testing.T) {
	resetDB(t)
	svc := NewDBServiceWithURL("file::memory:?cache=shared")
	// Insert a watchlist entry.
	_, err := keepAlive.Exec(`INSERT INTO user_watchlist (user_id, movie_id, watched) VALUES (?,?,?)`, 4, 40, true)
	if err != nil {
		t.Fatal(err)
	}
	// Remove the record.
	err = svc.RemoveFromWatchlist(4, 40)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify deletion.
	row := keepAlive.QueryRow(`SELECT COUNT(*) FROM user_watchlist WHERE user_id = ? AND movie_id = ?`, 4, 40)
	var count int
	if err := row.Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected record to be removed, count=%d", count)
	}
	// Try removing non-existing record.
	err = svc.RemoveFromWatchlist(4, 999)
	if err == nil || !strings.Contains(err.Error(), "movie not found in watchlist") {
		t.Errorf("expected error for non-existing record removal, got %v", err)
	}
}

// Test parseGenres directly.
func TestParseGenres(t *testing.T) {
	// Valid case.
	genreIDs := sql.NullString{String: "1,2", Valid: true}
	genreNames := sql.NullString{String: "Action,Comedy", Valid: true}
	genres := parseGenres(genreIDs, genreNames)
	if len(genres) != 2 {
		t.Fatalf("expected 2 genres, got %d", len(genres))
	}
	if genres[0].ID != 1 || genres[0].Name != "Action" {
		t.Errorf("unexpected first genre: %+v", genres[0])
	}
	if genres[1].ID != 2 || genres[1].Name != "Comedy" {
		t.Errorf("unexpected second genre: %+v", genres[1])
	}

	// Non-integer ID should be skipped.
	genreIDs = sql.NullString{String: "a,2", Valid: true}
	genreNames = sql.NullString{String: "Bad,Comedy", Valid: true}
	genres = parseGenres(genreIDs, genreNames)
	// Only the valid second genre should be added.
	if len(genres) != 1 || genres[0].ID != 2 {
		t.Errorf("expected only valid genre to be parsed, got: %+v", genres)
	}

	// When either is invalid.
	invalid := sql.NullString{Valid: false}
	genres = parseGenres(invalid, genreNames)
	if len(genres) != 0 {
		t.Errorf("expected empty result for invalid input, got: %+v", genres)
	}
}

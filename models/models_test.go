package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMovieStruct(t *testing.T) {
	movie := Movie{
		ID:           1,
		ImdbID:       "tt1234567",
		Title:        "Example Movie",
		VoteAverage:  7.5,
		Genres:       []Genre{{ID: 1, Name: "Action"}},
		CollectionID: nil,
	}

	assert.Equal(t, "Example Movie", movie.Title)
	assert.Equal(t, 7.5, movie.VoteAverage)

	jsonData, err := json.Marshal(movie)
	assert.NoError(t, err)

	var decoded Movie
	err = json.Unmarshal(jsonData, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, movie.Title, decoded.Title)
}

func TestGenreStruct(t *testing.T) {
	genre := Genre{
		ID:   2,
		Name: "Comedy",
	}
	assert.Equal(t, "Comedy", genre.Name)

	jsonData, err := json.Marshal(genre)
	assert.NoError(t, err)

	var decoded Genre
	err = json.Unmarshal(jsonData, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, genre.Name, decoded.Name)
}

func TestUserStruct(t *testing.T) {
	user := User{
		ID:       1,
		Username: "johndoe",
		Email:    "john@example.com",
		Password: "securepass",
	}
	assert.Equal(t, "johndoe", user.Username)

	jsonData, err := json.Marshal(user)
	assert.NoError(t, err)

	var decoded User
	err = json.Unmarshal(jsonData, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, decoded.Email)
}

func TestUserWatchlistStruct(t *testing.T) {
	watchlist := UserWatchlist{
		UserID:  10,
		MovieID: 20,
		Watched: true,
	}
	assert.True(t, watchlist.Watched)

	jsonData, err := json.Marshal(watchlist)
	assert.NoError(t, err)

	var decoded UserWatchlist
	err = json.Unmarshal(jsonData, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, watchlist.MovieID, decoded.MovieID)
}

func TestWatchlistItemStruct(t *testing.T) {
	item := WatchlistItem{
		MovieID:     123,
		Title:       "Movie Title",
		Watched:     false,
		VoteAverage: 8.1,
		Genres:      []Genre{{ID: 3, Name: "Drama"}},
	}
	assert.Equal(t, 123, item.MovieID)
	assert.False(t, item.Watched)

	jsonData, err := json.Marshal(item)
	assert.NoError(t, err)

	var decoded WatchlistItem
	err = json.Unmarshal(jsonData, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, item.Title, decoded.Title)
}

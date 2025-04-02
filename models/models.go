package models

type Movie struct {
	ID               int     `json:"id"`
	ImdbID           string  `json:"imdb_id"`
	Title            string  `json:"title"`
	OriginalTitle    string  `json:"original_title"`
	Overview         string  `json:"overview"`
	Tagline          string  `json:"tagline"`
	BackdropPath     string  `json:"backdrop_path"`
	PosterPath       string  `json:"poster_path"`
	Budget           int     `json:"budget"`
	Revenue          int     `json:"revenue"`
	Runtime          int     `json:"runtime"`
	ReleaseDate      string  `json:"release_date"`
	OriginalLanguage string  `json:"original_language"`
	VoteAverage      float64 `json:"vote_average"`
	VoteCount        int     `json:"vote_count"`
	Popularity       float64 `json:"popularity"`
	Status           string  `json:"status"`
	CollectionID     *int    `json:"collection_id,omitempty"`
	Genres           []Genre `json:"genres,omitempty"`
}

type Genre struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserWatchlist struct {
	UserID  int  `json:"user_id"`
	MovieID int  `json:"movie_id"`
	Watched bool `json:"watched"`
}

type WatchlistItem struct {
	MovieID      int     `json:"movie_id"`
	Title        string  `json:"title"`
	ReleaseDate  string  `json:"release_date"`
	Genres       []Genre `json:"genres"`
	Watched      bool    `json:"watched"`
	BackdropPath string  `json:"backdrop_path"`
	PosterPath   string  `json:"poster_path"`
	Runtime      int     `json:"runtime"`
	VoteAverage  float64 `json:"vote_average"`
}

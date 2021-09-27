package model

// Rank 排行榜
type Rank struct {
	Rank                int    `json:"rank"`
	UserID              string `json:"userID"`
	SolvedProblemNumber int    `json:"problemNumber"`
	SolvedProblemScore  int    `json:"problemScore"`
}

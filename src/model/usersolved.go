package model

// UserSolved 问题解答记录
type UserSolved struct {
	UserID          string  `json:"userID"`
	ProblemID       int     `json:"problemID"`
	ProblemTitle    string  `json:"problemTitle"`
	ProblemCategory string  `json:"problemField"`
	ProblemScore    int     `json:"problemScore"`
	Magnification   float32 `json:"magnification"`
	SolvedTime      string  `json:"solvedTime"`
}

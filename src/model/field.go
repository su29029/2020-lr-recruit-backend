package model

// Field 结构体
type Field struct {
	ProblemNumber         int    `json:"problemNumber"`
	MaxScore              int    `json:"maxScore"`
	CurrentMaxScore       int    `json:"currentMaxScore"`
	ChosenUserNumber      int    `json:"chosenUserNumber"`
	MaxSolved             int    `json:"maxSolved"`
	MaxSolvedProblemTitle string `json:"maxSolvedProblemTitle"`
	MinSolved             int    `json:"minSolved"`
	MinSolvedProblemTitle string `json:"minSolvedProblemTitle"`
}

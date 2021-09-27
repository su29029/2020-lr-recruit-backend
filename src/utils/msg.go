package utils

var MessageType map[string]int

func init() {
	MessageType = make(map[string]int)

	MessageType["NEW_UPLOAD"] = 0
	MessageType["NEW_FLAG_SUBMIT"] = 1
	MessageType["CORRECT_ANSWER"] = 2
	MessageType["NEW_PROBLEM"] = 3
	MessageType["HEART_BEAT"] = 4
	MessageType["ERROR"] = -1
}

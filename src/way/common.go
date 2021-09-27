package way

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"github.com/garyburd/redigo/redis"
	"github.com/gin-contrib/sessions"
	"github.com/gorilla/websocket"

	"github.com/gin-gonic/gin"

	"lrstudio.com/model"
	"lrstudio.com/utils"
)

// LoginIntercepter 用户登录信息检查
func LoginIntercepter() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		fmt.Println(path)
		if path == "/api/guest/login" || path == "/api/guest/islogin" || path == "/api/admin/login" || path == "/api/admin/islogin" || path == "/api/guest/validation" || path == "/api/guest/register" {
			c.Next()
		} else {
			session := sessions.Default(c)
			userID := session.Get("user")
			if userID == nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"msg": "session expired",
				})
				c.Abort()
			}
			c.Next()
		}
		c.Next()
	}
}

// SetSession 设置session
func SetSession(c *gin.Context, key string, value string, maxAge int) {
	session := sessions.Default(c)
	session.Set(key, value)
	session.Options(sessions.Options{
		MaxAge: maxAge,
	})
	err := session.Save()
	if err != nil {
		fmt.Println(err)
	}
}

// GetSession 获取session
func GetSession(c *gin.Context, key string) string {
	session := sessions.Default(c)
	v := session.Get(key)
	fmt.Println(key, v)
	if v == nil {
		return ""
	}
	return v.(string)
}

// DeleteSession 删除session
func DeleteSession(c *gin.Context, key string) bool {
	session := sessions.Default(c)
	session.Delete(key)
	session.Save()
	return true
}

// SetRedisPair 向Redis中写入数据
func SetRedisPair(key string, value string, expire int) bool {
	conn, err := redis.Dial("tcp", "redis:6379")
	if err != nil {
		fmt.Println("connect redis error :", err)
		return false
	}
	defer conn.Close()
	_, err = conn.Do("SET", key, value)
	if err != nil {
		fmt.Println("redis set error:", err)
		return false
	}
	_, err = conn.Do("expire", key, expire)
	if err != nil {
		fmt.Println("set expire error: ", err)
		return false
	}
	return true
}

// GetValueFromRedis 获取redis中的数据
func GetValueFromRedis(key string) string {
	conn, err := redis.Dial("tcp", "redis:6379")
	if err != nil {
		fmt.Println("connect redis error :", err)
	}
	defer conn.Close()
	code, err := redis.String(conn.Do("GET", key))
	if err != nil {
		fmt.Println("redis get error:", err)
	}
	return code
}

// NewClient 建立websocket连接后创建一个新的client结构以加入clientManager
func NewClient(addr string, userID string, socket *websocket.Conn) (client *model.Client) {
	for clients := range model.Manager.Clients {
		if clients.UserID == userID && clients.Addr == addr {
			return nil
		}
	}
	client = &model.Client{
		UserID: userID,
		Addr:   addr,
		Socket: socket,
		Send:   make(chan model.Message, 100),
	}
	return client
}

// SendMsg 向手机发送验证码
func SendMsg(tel string, code string) string {
	client, err := dysmsapi.NewClientWithAccessKey("cn-hangzhou", "LTAI4G2m2K4DXuYYjAmdRWDV", "2HIHJNRkXr2iiHIxaP3Aj9CWh53GKV")
	request := dysmsapi.CreateSendSmsRequest()
	request.Scheme = "https"
	request.PhoneNumbers = tel
	request.SignName = "凌睿工作室"
	request.TemplateCode = "SMS_195863875"
	request.TemplateParam = "{\"code\":\"" + code + "\"}"
	response, err := client.SendSms(request)
	fmt.Println(response.Code)
	if response.Code == "isv.BUSINESS_LIMIT_CONTROL" {
		return "frequency_limit"
	}
	if err != nil {
		fmt.Print(err.Error())
		return "failed"
	}
	return "success"
}

// Code 随机验证码
func Code() string {
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(899999) + 100000
	res := strconv.Itoa(code)
	return res
}

// Validation 在注册时检查验证码
func Validation(validation string, tel string) int {
	var flag int
	getcode := GetValueFromRedis(tel)

	if validation == getcode {
		flag = 1
	} else {
		flag = 0
	}
	return flag
}

// CheckInformation 检查用户信息合法性
func CheckInformation(information interface{}) bool {
	var result bool = true
	switch information.(type) {
	case model.Profile:
		var profile = information.(model.Profile)
		if profile.NewPassword != profile.RepeatPassword {
			fmt.Println("password wrong")
			result = false
			return result
		}
		fmt.Println(len(profile.OldPassword))
		fmt.Println(len(profile.NewPassword))
		fmt.Println(len(profile.RepeatPassword))
		if !checkUserName(profile.UserID) {
			fmt.Println("userID invalid")
			result = false
		} else if (len(profile.OldPassword) < 8 && len(profile.OldPassword) != 0) || len(profile.OldPassword) > 32 {
			fmt.Println("oldpassword invalid")
			result = false
		} else if !checkStudentID(profile.StudentID) {
			fmt.Println("studentid invalid")
			result = false
		} else if !checkQQNumber(profile.QQNumber) {
			fmt.Println("qq invalid")
			result = false
		} else if !checkEmail(profile.Email) {
			fmt.Println("email invalid")
			result = false
		} else if !checkPhoneNumber(profile.Tel) {
			fmt.Println("tel invalid")
			result = false
		} else if (len(profile.NewPassword) < 3 && len(profile.NewPassword) != 0) || len(profile.NewPassword) > 32 {
			fmt.Println("newpass invalid")
			result = false
		} else if (len(profile.RepeatPassword) < 3 && len(profile.RepeatPassword) != 0) || len(profile.RepeatPassword) > 32 {
			fmt.Println("repeat invalid")
			result = false
		}
		break
	case model.UserInformation:
		var user = information.(model.UserInformation)
		if len(user.UserID) < 3 || len(user.UserID) > 20 {
			result = false
		} else if len(user.Passwd) < 8 || len(user.Passwd) > 32 {
			result = false
		} else if !checkStudentID(user.StudentID) {
			result = false
		} else if !checkPhoneNumber(user.Tel) {
			result = false
		}
		break
	}
	return result
}

// Md5 将字符串转化成md5
func Md5(str string) string {
	hash := md5.Sum([]byte(str))
	return hex.EncodeToString(hash[:])
}

func Base64Encode(str string) string {
	data := []byte(str)
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(str string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func checkUserName(userID string) bool {
	re := regexp.MustCompile(`^[0-9a-zA-Z_]{3,20}$`)
	result := re.MatchString(userID)
	return result
}

func checkStudentID(studentID string) bool {
	re := regexp.MustCompile(`^((2021\d{9})|(2020\d{9})|(2019\d{9})|(2018\d{9})|(2017\d{9}))$`)
	result := re.MatchString(studentID)
	return result
}

func checkPhoneNumber(tel string) bool {
	re := regexp.MustCompile(`^((0\d{2,3}-\d{7,8})|(1[3658479]\d{9}))$`)
	result := re.MatchString(tel)
	return result
}

func checkQQNumber(qqNumber string) bool {
	if len(qqNumber) == 0 {
		result := true
		return result
	}
	re := regexp.MustCompile(`^[1-9]\d{4,10}$`)
	result := re.MatchString(qqNumber)
	return result
}

func checkEmail(email string) bool {
	if len(email) == 0 {
		result := true
		return result
	}
	re := regexp.MustCompile(`^([A-Za-z0-9_\-\.\\u4e00-\\u9fa5])+\@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,8})$`)
	result := re.MatchString(email)
	return result
}

// GuestGetProblemsByField 用户页面 通过field获取所有可见题目所有信息
func GuestGetProblemsByField(FieldID int, userID string) ([]model.Problems, error) {
	var problems []model.Problems
	var problem model.Problems
	var problemIDs []int
	var sqlStr string
	var rows *sql.Rows
	var err error
	sqlStr = "select problem_id, problem_title, problem_score, current_score, problem_category, problem_solved from problem_table where problem_category = ? and is_show = 1 order by sort_id"
	rows, err = utils.Db.Query(sqlStr, FieldID)
	if err != nil {
		return problems, err
	}
	for rows.Next() {
		rows.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemCategory, &problem.ProblemSolved)
		fmt.Println(problem)
		problems = append(problems, problem)
		problemIDs = append(problemIDs, problem.ProblemID)
	}

	sqlStr = fmt.Sprintf("select solved_problem_id from problem_solved_table where userId = \""+userID+"\" and solved_problem_id in (%s)", placeHolders(len(problemIDs)))

	rows, err = utils.Db.Query(sqlStr, transferToInterface(problemIDs)...)
	if err != nil {
		fmt.Println(err)
		return problems, nil
	}
	for rows.Next() {
		var tmpProblemID int
		rows.Scan(&tmpProblemID)
		for i, problem := range problems {
			if tmpProblemID == problem.ProblemID {
				problems[i].HasSolved = true
			}
		}
	}
	return problems, nil
}

// GuestGetProblemDetailByID 用户页面 通过id获取某一题目的内容信息
func GuestGetProblemDetailByID(id int) (model.Problems, error) {
	var problem model.Problems
	sqlStr := "select problem_id, problem_title, problem_content, problem_score, current_score, problem_category, problem_solved, flag, is_show from problem_table where problem_id = ?"
	row := utils.Db.QueryRow(sqlStr, id)

	row.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemContent, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemCategory, &problem.ProblemSolved, &problem.Flag, &problem.IsShow)
	if problem.Flag != "" {
		problem.Flag = ""
		problem.ProblemType = "flag"
	} else {
		problem.ProblemType = "upload"
	}
	return problem, nil
}

// AdminGetFieldOverview 管理员页面 获取detail页面某个field的概况信息
func AdminGetFieldOverview(field int) (model.Field, error) {
	var overview model.Field
	var sqlStr string

	// 获取题目总数
	sqlStr = "select count(*) from problem_table where problem_category = ?"
	row := utils.Db.QueryRow(sqlStr, field)

	row.Scan(&overview.ProblemNumber)

	// 获取最大分数
	sqlStr = "select sum(current_score) from problem_table where problem_category = ?"
	row = utils.Db.QueryRow(sqlStr, field)

	row.Scan(&overview.MaxScore)

	// 获取当前最高分
	sqlStr = "select sum(solved_problem_score * magnification) as 'score' from problem_solved_table where solved_problem_field = ? group by userId limit 0,1"
	row = utils.Db.QueryRow(sqlStr, field)
	row.Scan(&overview.CurrentMaxScore)

	// 选择用户人数
	sqlStr = "select count(distinct userId) as num from problem_solved_table where solved_problem_field= ? "
	row = utils.Db.QueryRow(sqlStr, field)
	row.Scan(&overview.ChosenUserNumber)

	// 最大解出题目
	sqlStr = "select problem_solved, problem_title from problem_table where problem_category = ? order by problem_solved desc"
	row = utils.Db.QueryRow(sqlStr, field)
	row.Scan(&overview.MaxSolved, &overview.MaxSolvedProblemTitle)

	// 最小解出题目
	sqlStr = "select problem_solved, problem_title from problem_table where problem_category = ? order by problem_solved"
	row = utils.Db.QueryRow(sqlStr, field)
	row.Scan(&overview.MinSolved, &overview.MinSolvedProblemTitle)

	return overview, nil
}

// AdminGetFieldDetail 管理员页面 获取detail页面的题目信息
func AdminGetFieldDetail(field int) ([]model.Problems, error) {
	var problems []model.Problems
	var problem model.Problems
	sqlStr := "select problem_id, problem_title, problem_score, current_score, problem_solved, first_blood from problem_table where problem_category = ?"
	rows, err := utils.Db.Query(sqlStr, field)

	if err != nil {
		fmt.Println(err)
		return problems, err
	}
	for rows.Next() {
		rows.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemSolved, &problem.FirstBlood)
		problems = append(problems, problem)
	}

	return problems, nil
}

// AdminGetProblemsByField 管理员页面 通过field获取problem页面题目信息
func AdminGetProblemsByField(field int) ([]model.Problems, error) {
	var problems []model.Problems
	var problem model.Problems
	sqlStr := "select problem_id, problem_title, problem_content, problem_score, current_score, problem_solved, flag, is_show from problem_table where problem_category = ? order by sort_id"
	rows, err := utils.Db.Query(sqlStr, field)

	if err != nil {
		fmt.Println(err)
		return problems, err
	}
	for rows.Next() {
		rows.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemContent, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemSolved, &problem.Flag, &problem.IsShow)
		fmt.Println(problem)
		problems = append(problems, problem)
	}
	return problems, nil
}

// DealWithBlankProblem 处理空问题
func DealWithBlankProblem() {
	var sqlStr string
	var err error
	sqlStr = "delete from problem_table where problem_title = '' and problem_content = ''"
	for range time.Tick(time.Minute * 5) {
		_, err = utils.Db.Exec(sqlStr)
		if err != nil {
			fmt.Println("deal blank problem error")
		}
	}
}

func transferToInterface(v interface{}) []interface{} {
	val, ok := isSlice(v)

	if !ok {
		return nil
	}

	sliceLen := val.Len()

	out := make([]interface{}, sliceLen)

	for i := 0; i < sliceLen; i++ {
		out[i] = val.Index(i).Interface()
	}

	return out
}

func isSlice(v interface{}) (val reflect.Value, ok bool) {
	val = reflect.ValueOf(v)

	if val.Kind() == reflect.Slice {
		ok = true
	}

	return
}

func placeHolders(n int) string {
	ps := make([]string, n)
	for i := 0; i < n; i++ {
		ps[i] = "?"
	}
	return strings.Join(ps, ",")
}

// Unsafe 过滤一下危险字符防注入
func Unsafe(param string) bool {
	reg := regexp.MustCompile(`'|"|select|union|insert|delete|if|case|update`)
	if len(reg.FindAllString(param, -1)) > 0 {
		return true
	}
	return false
}

// IsFileExist 检查名为 filename 的文件是否存在
func IsFileExist(fileName string) (bool, error) {
	_, err := os.Stat(fileName)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CreateDir 在'/home/lr/upload'创建用户上传目录
func CreateDir(userID string) bool {
	dst := path.Join("/app/upload", userID)
	err := os.MkdirAll(dst, os.ModePerm)
	if err != nil {
		fmt.Println("create failed: ", err)
		return false
	}
	return true
}

// SplitUploadFileNameToUploadType 将上传文件名中的上传人和题目id提取出来，供admin problem页面题目提交情况展示
func SplitUploadFileNameToUploadType(uploadFileName string) model.Upload {
	var upload model.Upload

	lastUnder := strings.LastIndex(uploadFileName, "_")
	firstUnder := strings.Index(uploadFileName, "_")
	uploadFileName = uploadFileName[firstUnder+1 : lastUnder]
	upload.UploadUser = uploadFileName[:strings.LastIndex(uploadFileName, "_")]
	upload.ProblemID, _ = strconv.Atoi(uploadFileName[strings.LastIndex(uploadFileName, "_")+1:])

	return upload
}

// PlaceHolders sql格式化
func PlaceHolders(n int) string {
	ps := make([]string, n)
	for i := 0; i < n; i++ {
		ps[i] = "?"
	}
	return strings.Join(ps, ",")
}

// TransferToInterface v interface{} -> []interface{}
func TransferToInterface(v interface{}) []interface{} {
	val, ok := isSlice(v)

	if !ok {
		return nil
	}

	sliceLen := val.Len()

	out := make([]interface{}, sliceLen)

	for i := 0; i < sliceLen; i++ {
		out[i] = val.Index(i).Interface()
	}

	return out
}

// CalculateCurrentScore 计算动态分数
func CalculateCurrentScore(problemScore int, problemSolved int, decay int) int {
	var value float64 = 0
	if problemSolved == 0 {
		return int(problemScore)
	}
	if problemSolved >= decay {
		return int(0.1 * float64(problemScore))
	}
	value = math.Ceil((((0.1*float64(problemScore) - float64(problemScore)) / float64(decay*decay)) * float64(problemSolved*problemSolved)) + float64(problemScore))
	return int(value)
}

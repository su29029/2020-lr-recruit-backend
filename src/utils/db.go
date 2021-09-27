package utils

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var (
	Db  *sql.DB
	err error
)

func init() {
	dsn := "root:tF#262420228@tcp(mysql:3306)/lr?charset=utf8mb4"
	Db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err.Error())
	}
}

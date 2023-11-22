package vlog

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "", 0)

func Println(v ...interface{}) {
	logger.Println(v...)
}

func Fatalln(v ...interface{}) {
	logger.Fatalln(v...)
}

func Fatalf(format string, v ...interface{}) {
	logger.Fatalf(format, v...)
}

func Printf(format string, v ...interface{}) {
	logger.Printf(format, v...)
}

func Fatal(v ...interface{}) {
	logger.Fatal(v...)
}

package main

import (
	"fmt"
	"log"

	"github.com/shubhkasyap1/go-backend-task/internal/cli"
)

func main() {
	fmt.Println("=================================")
	fmt.Println("   Go Authentication CLI")
	fmt.Println("=================================")
	fmt.Println()

	app, err := cli.NewApp()
	if err != nil {
		log.Fatal(err)
	}

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

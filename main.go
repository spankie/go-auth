package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/spankie/go-auth/db"
	"github.com/spankie/go-auth/router"
	"github.com/spankie/go-auth/server"
)

func main() {
	env := os.Getenv("GIN_MODE")
	if env != "release" {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("couldn't load env vars: %v", err)
		}
	}

	DB := &db.MongoDB{}
	DB.Init()
	s := &server.Server{
		DB:     DB,
		Router: router.NewRouter(),
	}
	s.Start()
}

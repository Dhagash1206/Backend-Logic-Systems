	// Starts the PocketBase server:
	// - REST API + built-in JWT auth on the "users" collection
	// - Admin UI at /_/
	// - SQLite database stored in ./pb_data
	// Default address: http://127.0.0.1:8090



package main

import (
	"log"

	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

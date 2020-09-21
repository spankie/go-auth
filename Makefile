
start-db:
	brew services start mongodb-community@4.2

stop-db:
	brew services stop mongodb-community@4.2

mock-db:
	mockgen -source=db/db.go -destination=db/mock_db.go -package=db

test: mock-db
	GIN_MODE=test go test ./...
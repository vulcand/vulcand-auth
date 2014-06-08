test:
	go test -v ./auth

cover:
	go test -v ./auth  -coverprofile=/tmp/coverage.out
	go tool cover -html=/tmp/coverage.out

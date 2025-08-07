run-test:
	go run cmd/test/test.go

run:
	go run .

build-container:
	docker build -t doscrape-token-collector .


migration-up:
	migrate -path ./migrations -database 'postgres://admin:admin@localhost:5432/rentcar?sslmode=disable' up
	
migration-down:
	migrate -path ./migrations -database 'postgres://admin:admin@localhost:5432/rentcar?sslmode=disable' down
	
migration-force-1v:
	migrate -path ./migrations -database 'postgres://admin:admin@localhost:5432/rentcar?sslmode=disable' force 1


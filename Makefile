build:
	docker-compose --env-file .docker-compose.env up -d --build app nginx

up:
	docker-compose --env-file .docker-compose.env up -d app nginx

down:
	docker-compose --env-file .docker-compose.env down

restart:
	@$(MAKE) -s down
	@$(MAKE) -s up



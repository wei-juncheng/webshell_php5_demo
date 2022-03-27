build:
	docker-compose up -d --build app nginx

up:
	docker-compose up -d app nginx

down:
	docker-compose down

restart:
	@$(MAKE) -s down
	@$(MAKE) -s up



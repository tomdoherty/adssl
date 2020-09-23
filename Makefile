all:
	@$(MAKE) lint
	@$(MAKE) build

lint:
	./scripts/lint.sh

build:
	./scripts/build.sh

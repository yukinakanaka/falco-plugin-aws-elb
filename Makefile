SHELL=/bin/bash -o pipefail
CARGO ?= cargo

NAME := awselb
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUT) && rm -rf target

PHONY: $(OUTPUT)
$(OUTPUT): 
	 $(CARGO) build --release && mv target/release/libawselb.so .

PHONY: debug
debug: 
	 $(CARGO) build && mv target/debug/libawselb.so .

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md


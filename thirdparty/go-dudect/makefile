BIN = dudect
SRC = dudect.go utils.go

.DEFAULT_GOAL = build

.PHONY: clean format examples

build:
	@echo "Please name the file in which you have your function, e.g: make rsa"

%:  %.go $(SRC)
			go build -o $(BIN) $(SRC) $*.go

clean:         
	        rm -f $(BIN); 

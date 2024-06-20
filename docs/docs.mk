.PHONY: docs
docs:
	mkdir -p build
	docker run \
		--rm \
		-v "$(KRYPTON_PRIMITIVES_HOME)":/krypton-primitives \
		-w /krypton-primitives/docs \
		texlive/texlive:latest-full \
		latexmk \
			-bibtex \
			--max-print-line=10000 \
			-synctex=1 \
			-aux-directory="build" \
			-output-directory="build" \
			-view=none \
			-pdf \
			main.tex

clean-docs:
	docker run \
		-v "$(KRYPTON_PRIMITIVES_HOME)":/krypton-primitives \
		-w /krypton-primitives/docs \
		texlive/texlive:latest-full \
		latexmk -c \
			-bibtex \
			-aux-directory="build" \
			-output-directory="build" \
			main.tex
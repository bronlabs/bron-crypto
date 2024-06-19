.PHONY: docs
docs:
	mkdir -p build
	docker run \
		-v "$(PWD)":/krypton-primitives \
		-w /krypton-primitives/docsStandalone \
		texlive/texlive:latest-full \
		latexmk \
			--max-print-line=10000 \
			-synctex=1 \
			-aux-directory="build" \
			-output-directory="build" \
			-view=none \
			-pdf \
			main.tex

clean:
	docker run \
		-v "$(PWD)":/krypton-primitives \
		-w /krypton-primitives/docsStandalone \
		texlive/texlive:latest-full \
		latexmk -c
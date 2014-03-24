.PHONY: all doc clean
PDFLATEX=pdflatex
NOWEAVE=noweave -filter "elide comment:*"
NOTANGLE=notangle
all: output/main.pdf
doc: output/main.pdf
	okular $<
output/%.tex: %.nw makefile
	mkdir -p output
	$(NOWEAVE) -n -index -autodefs promela -latex $< >$@
output/%.pml: %.nw makefile
	$(NOTANGLE) -L $< >$@
output/main.pdf: output/gc.tex makefile main.tex
	$(PDFLATEX) -file-line-error -halt-on-error -output-directory output main.tex
	$(PDFLATEX) -file-line-error -interaction batchmode -halt-on-error -output-directory output main.tex
	$(PDFLATEX) -file-line-error -interaction batchmode -halt-on-error -output-directory output main.tex
clean:
	rm -rf output

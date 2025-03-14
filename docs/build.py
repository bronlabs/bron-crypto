from pathlib import Path
import argparse
import subprocess
import jinja2

BRON_CRYPTO_URL = "https://github.com/bronlabs/bron-crypto"


def setup():
    """Processes the paths to known folders, and creates the `build` folder"""
    global docs_folder, standalone_algorithms_folder, standalone_pdf_folder
    global root_path, pkg_path, docs_path, build_path, templates_path

    # Process all paths
    docs_folder = Path("docs")
    standalone_algorithms_folder = docs_folder / "algorithms"
    standalone_pdf_folder = docs_folder

    root_path = Path(".").resolve()
    pkg_path = root_path / "pkg"
    docs_path = root_path / docs_folder
    build_path = docs_path / "build"
    templates_path = docs_path / "src" / "templates"

    if root_path.name != "bron-crypto" or not (
        pkg_path.exists() and docs_path.exists() and templates_path.exists()
    ):
        raise RuntimeError(
            "This script must be run from the bron-crypto root folder"
        )
    build_path.mkdir(exist_ok=True)


def buildLatex(tex_file: Path, verbose: bool = False):
    """Builds a LaTeX file using the texlive docker image."""
    if not tex_file.exists():
        raise RuntimeError(f"Expected the LaTeX file {tex_file} to exist")
    if not tex_file.suffix == ".tex":
        raise RuntimeError(
            f"Expected the LaTeX file {tex_file} to have a .tex extension"
        )
    if not tex_file.parent == docs_path:
        raise RuntimeError(f"Expected {tex_file} inside {docs_path.name}")

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",  # Remove container after running
            "-v",
            f"{str(root_path)}:/bron-crypto",  # Mount the main dir
            "-w",
            "/bron-crypto/docs",  # Set working dir to main `docs`
            "texlive/texlive:latest-full",  # Use the texlive docker image
            "latexmk",  # Run the latexmk command...
            "-synctex=1",  # ...with synctex (click on PDF)...
            "-aux-directory=build",  # ...with the build dir for aux files...
            "-output-directory=build",  # ...outputting the PDF there...
            "-pdf",  # ...generating a PDF...
            "-view=none",  # ...without opening the PDF after compilation...
            str(tex_file.name),  # ...for this .tex file in the `docs` dir.
        ],
        cwd=root_path,
        stdout=None if verbose else subprocess.DEVNULL,
        stderr=subprocess.STDOUT if verbose else subprocess.DEVNULL,
    )


def buildStandaloneLatex(standalone_file: Path, verbose: bool = False):
    """Builds a standalone algorithm LaTeX file and moves the generated PDF to
    the corresponding package directory."""
    # Determine the path to the Go package where the standalone file is located
    if standalone_file.parent.parent.name != "docs":
        raise RuntimeError(
            f"Expected the standalone file {standalone_file} to be inside \
              a '*/docs/*/*.tex' directory structure"
        )
    go_pkg = standalone_file.relative_to(pkg_path).parent.parent.parent
    print(f"Processing {standalone_file.relative_to(root_path)}")

    # Load the template
    template = jinja2.Environment(
        loader=jinja2.FileSystemLoader(templates_path)
    ).get_template("standalone_algorithm.jinja")

    # Render the template
    filled_template = template.render(
        input_cmd=f"\\inputAlgorithm{{{go_pkg}}}{{{standalone_file.name}}}",
        pkg_url_cmd=f"\\href{{{BRON_CRYPTO_URL}/{go_pkg}}}{{{go_pkg}}}",
    )

    # Write the filled template to the `docs` directory
    tex_file_path = docs_path / standalone_file.name.replace(
        ".tex", "_standalone.tex"
    )
    with tex_file_path.open("w") as f:
        f.write(filled_template)

    # Compile the LaTeX file /docs/*.tex into a /docs/build/*.pdf file
    buildLatex(tex_file_path, verbose)

    # Move the generated PDF to its corresponding location in its package
    pdf_path = build_path / tex_file_path.name.replace(".tex", ".pdf")
    pdf_destination = pkg_path / go_pkg / standalone_pdf_folder / pdf_path.name
    pdf_path.replace(pdf_destination)

    print(f"Generated {pdf_destination.relative_to(root_path)}")

    # Clean up the generated LaTeX file
    tex_file_path.unlink()


def buildStandaloneAlgorithms(standalone_path: Path, verbose: bool = False):
    """Builds all standalone algorithms present in `docs/algorithms`
    directories across all go packages."""
    if not standalone_path.exists():
        raise RuntimeError(f'Expected "{standalone_path}" to exist')
    standalone_path = standalone_path.resolve()
    if not standalone_path.is_dir():
        raise RuntimeError(f'Expected "{standalone_path}" to be a dir')
    if not standalone_path.is_relative_to(pkg_path):
        raise RuntimeError(f"Expected \"{standalone_path}\" inside 'pkg'")

    # Apply the template to all '*/docs/algorithms/*.tex' files
    algorithms = list(
        standalone_path.rglob(f"{str(standalone_algorithms_folder)}/*.tex")
    )
    if len(algorithms) == 0:
        raise RuntimeError(f"No standalone algorithms in {standalone_path}")
    print("Processing %d algorithm(s)..." % len(algorithms))
    for algorithm in algorithms:
        buildStandaloneLatex(algorithm, verbose)


def cleanLatex():
    """Cleans the build directory of all files except the main PDF."""
    for f in build_path.iterdir():
        if f.is_file() and f.name != "main.pdf":
            f.unlink()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build bron crypto docs from LaTeX files"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--main", action="store_true", help="Build the spec")
    group.add_argument(
        "--standalone-path",
        type=str,
        required=False,
        help="Build standalone docs under this path",
    )

    parser.add_argument(
        "--clean", action="store_true", help="Clean the build directory"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the output of the LaTeX build command",
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    setup()
    args = parse_args()

    if args.main:
        main_file = docs_path / "main.tex"
        buildLatex(main_file, verbose=args.verbose)
        print(f"Generated {(build_path / 'main.pdf').relative_to(root_path)}")
    elif args.standalone_path:
        if args.standalone_path == "all":
            buildStandaloneAlgorithms(pkg_path, verbose=args.verbose)
        else:
            buildStandaloneAlgorithms(
                pkg_path / args.standalone_path, verbose=args.verbose
            )

    if args.clean:
        cleanLatex()

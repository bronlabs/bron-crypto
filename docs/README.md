# Krypton Primitives Specification
This repository contains the Latex skeleton for the cryptographic specification of the `krypton-primitives` library. The specification is written in Latex and is divided into several sections, drawing most of its content from the `docs` folders inside most packages in source code of the library.

--------------------------
--------------------------

## Releases
The `docs/release` folder contains the latest release of the specification. The release is a PDF file that can be downloaded and shared. Upon a new release, the PDF file is to be updated and the previous release is either archived in the `docs/release/archive` folder or removed.


## Building the docs

The docs are build using `latexmk` in a docker container with a full TeXLive installation. To build the docs, you need to have `docker` installed on your machine. If document generation fails silently, uncomment the `VERBOSE` variable in the `docs.mk` file to see the full output of the `latexmk` command.

#### The spec
To build the main spec, run from the krypton-primitives root folder:

```bash
make spec
```

#### Standalone algorithms in a certain package

To build the standalone algorithms in a certain package, run from the krypton-primitives root folder:

```bash
make standalone-docs KRYPTON_PKG="<package>"
```

where `<package>` is the name of the package you want to build the standalone algorithms for, relative to the `pkg` folder (e.g., `tanscripts`, `csprng/krand`)

#### All standalone algorithms

To build all standalone algorithms, run from the krypton-primitives root folder:

```bash
make all-standalone-docs
```

#### Debugging docs build issues
If no PDF is generated, run the build command with the `VERBOSE` variable set to `--verbose`. E.g., (for the main spec) run from the krypton-primitives root folder:

```bash
make spec VERBOSE="--verbose"
```

## Cleaning the docs

To clean the docs, run from the krypton-primitives root folder:

```bash
make clean-docs
```

This will remove all the generated files in the `docs/build` folder except for the `docs/build/main.pdf` file.


## FAQ

**What are the overall elements of a doc inside of a package ie. section/algorithm/functionality/protocol? etc and how to write one.**

A doc inside a package can contain the following elements:
- `pkg/**/docs/section/*.tex`: Descriptions of the package from a high level perspective, with words and avoiding pseudo-code.
- `pkg/**/docs/algorithm/*.tex`: Detailed descriptions of the algorithm/scheme/protocol, including only the algorithm itself in pseudo-code inside a `algorithm`/`scheme`/`protocol` environment.
- `pkg/**/docs/functionality/*.tex`: Detailed descriptions of the UC ideal functionality of the package, including only the functionality in pseudo-code inside a `functionality` environment.

Packages can contain any combination of these elements, but none are required. There can be multiple sections, algorithms, and functionalities in a single package.

To tie these elements together, the `krypton-primitives/docs/src` folder contains the skeleton of the full specification document, with a `main.tex` file that includes all the sections, algorithms, and functionalities in the correct order.

To write a new doc inside a package, create a new `.tex` file in the `pkg/**/docs/section`, `pkg/**/docs/algorithm`, or `pkg/**/docs/functionality` folder, and include it in the appropriate section in the `docs/src` folder. Use an existing `.tex` file from another package as template.

**How to generate spec for a package.**
Each package with an existing `**/docs/algorithms/*.tex` file can be built as a standalone document with the `make standalone-docs KRYPTON_PKG="<package>"` command (see above). This will generate a standalone PDF file for the package in that package's `**/docs` folder.

**How to generate spec for threshold signing.**
The full spec contains a section on threshold signing. To generate the full spec, run `make spec` from the krypton-primitives root folder.

If a specific threshold signing spec is desired, strip the relevant parts from the `docs/main.tex` file and include them in a new `.tex` file in the `docs/src` folder. Then adapt the `docs.mk` build command alongside the `docs/build.py` script to manage the new file instead of the original `main.tex` (without the standalone machinery).

**What to do if we want to have another spec composed of multiple different packages.**
Elements from the packages can be imported and composed as many times as you see fit, as long as you use separate `main.tex` files (note that you can change the name of the main file!). Follow the steps on the question just above (threshold signing).


**Setup**
The spec build requires `docker` installed and running on your machine. It will use a docker container with a full TeXLive installation to build the docs. To build the docs, you need `python` and `pip` installed on your machine, at which point a `make deps-docs` command will install the required python packages (see the `docs/requirements.txt` file). No other dependencies are required.


**Policies and guidelines to avoid duplicate commands, notations or references etc.**
Notation, commands and bibliography are shared across all main `.tex` files. Before adding a new command, notation, or reference, check the existing documentation to see if it already exists:
- Commands are defined in the `docs/src/headers/spec_header.tex` file.
- Notations are defined in the `docs/src/headers/spec_header.tex` file.
- Bibliography entries are defined in the `docs/src/bib/*.bib` files. You can add new entries to these files or create a new `.bib` file and append it both to the `docs/main.tex` and the `docs/src/templates/standalone_algorithm.jinja` files.

Upon creation of a new notation element, add one example of its usage in the `docs/src/figures/notation.tex` file. I recommend https://latex.codecogs.com/eqneditor/editor.php for creating LaTeX equations and deciding what to put in your new command if it is of mathematical nature.

**Adding a diagram / image**
To add a diagram or image to the spec, place the image in the `docs/src/assets` folder. Then, include the image in the appropriate `.tex` file using the `\includegraphics` command.

**Version management for global docs.**

The `build` folder contains the generated PDF files for the main spec. The `release` folder contains the latest release of the spec. Upon a new release, the PDF file is to be updated and the previous release is either archived in the `docs/release/archive` folder or removed. There should always be both a single latest release in the `docs/release` folder, and a `docs/build/main.pdf` file.

**Is it an Algorithm, a Scheme or a Protocol?**
An algorithm is a set of instructions, a.k.a. a single function. A scheme is a set of algorithms that work together (e.g., Commitments). A protocol is a set of numbered `Round` algorithms that rely on a state and messages to be exchanged between parties.
//go:generate sh -c "docker run --rm -v \"$(pwd):/tmp\" -w /tmp -u\"${UID}:${GID}\" -e GOFILE --platform=linux/amd64 sagemath/sagemath:latest sage ./fp3.sage"
package vectors

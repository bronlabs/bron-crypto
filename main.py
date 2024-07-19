import subprocess

# linters = ["err113" "exhaustive" "exportloopref" forbidigo forcetypeassert gci gocheckcompilerdirectives gochecknoinits gochecksumtype goconst gocritic godot gofmt gomoddirectives goprintffuncname gosec gosimple gosmopolitan govet importas inamedparam ineffassign loggercheck makezero mirror misspell nakedret nilerr nilnil noctx nolintlint nosprintfhostport prealloc predeclared promlinter revive rowserrcheck sqlclosecheck staticcheck tagalign tagliatelle tenv testableexamples testifylint thelper tparallel unconvert unparam unused usestdlibvars wastedassign whitespace wrapcheck zerologlint]

linters = ["asasalint", "asciicheck", "bidichk", "bodyclose", "containedctx", "contextcheck", "copyloopvar", "depguard", "dogsled", "dupl", "dupword", "durationcheck", "err113", "errcheck", "errchkjson", "errname", "errorlint", "exhaustive", "exportloopref", "forbidigo", "forcetypeassert", "gci", "gocheckcompilerdirectives", "gochecknoinits", "gochecksumtype", "goconst", "gocritic", "godot", "gofmt", "gomoddirectives", "goprintffuncname", "gosec", "gosimple", "gosmopolitan", "govet", "importas", "inamedparam", "ineffassign", "loggercheck", "makezero", "mirror", "misspell", "nakedret", "nilerr", "nilnil", "noctx", "nolintlint", "nosprintfhostport", "prealloc", "predeclared", "promlinter", "revive", "rowserrcheck", "sqlclosecheck", "staticcheck", "tagalign", "tagliatelle", "tenv", "testableexamples", "testifylint", "thelper", "tparallel", "unconvert", "unparam", "unused", "usestdlibvars", "wastedassign", "whitespace", "wrapcheck", "zerologlint"] 

cmd = "golangci-lint cache clean &&  golangci-lint run --verbose --timeout=120m --print-resources-usage --disable-all --enable="

outfile_file = 'output.txt'
outfile_debugfile = 'outputdebug.txt'

def runDebugLinters(file):

    # run cmd
    result = subprocess.run("golangci-lint cache clean && GL_DEBUG=goanalysis/analyze,goanalysis/facts,goanalysis/memory golangci-lint run --verbose --timeout=120m", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    file.write(f"Results for debug:\n")
    file.write(result.stdout.decode())
    file.write("\n" + "="*40 + "\n")

def runLinters(linterToRun, file, i):
    linters_str = ",".join(linterToRun)
    cmd = f"golangci-lint cache clean &&  golangci-lint run --verbose --timeout=120m --print-resources-usage --disable-all --enable={linters_str}"
    print(str(i) + "\n"+ str(linterToRun))
    # run cmd
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    file.write(f"Results for {linterToRun}:\n")
    file.write(result.stdout.decode())
    file.write("\n" + "="*40 + "\n")

with open(outfile_file, 'a') as file:
    for i in range(len(linters)):
        lintersToRun = linters[i:]
        runLinters(lintersToRun, file, i)

with open(outfile_file, 'a') as file:
    runDebugLinters(file)


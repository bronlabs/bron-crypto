#!/usr/bin/env sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 golangci-lint|revive|nancy"
fi

TOOL_NAME="$1"

case "$TOOL_NAME" in
    golangci-lint)
        if command -v brew > /dev/null; then
            brew upgrade golangci-lint  || brew install golangci-lint
        else
            curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)/bin" latest
        fi
        ;;
    revive)
        go install github.com/mgechev/revive@latest
        ;;
    nancy)
        if command -v brew > /dev/null; then
            brew upgrade nancy || brew install sonatype-nexus-community/nancy-tap/nancy
        else
            REPO="https://github.com/sonatype-nexus-community/nancy/releases"
            URL=$(curl -sL -o /dev/null -w "%{url_effective}" "${REPO}/latest")
            TAG_VERSION=$(echo "$URL" | awk -F'/tag/' '{print $2}')
            curl -sSfL "${REPO}/download/${TAG_VERSION}/nancy_${TAG_VERSION#?}_linux_amd64.apk" -o ./nancy.apk && apk add --allow-untrusted ./nancy.apk && rm ./nancy.apk
        fi
        ;;
esac

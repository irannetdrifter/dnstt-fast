#!/bin/bash
#
# Build script for DNSTT Android app
# Builds Go library with gomobile and the Android app
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}DNSTT Android Build Script${NC}"
echo "=============================="

# Check for required tools
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

check_tool go

# Find or install gomobile
GOPATH="${GOPATH:-$HOME/go}"
GOMOBILE="$GOPATH/bin/gomobile"

if ! command -v gomobile &>/dev/null && [ ! -f "$GOMOBILE" ]; then
    echo -e "${BLUE}Installing gomobile...${NC}"
    go install golang.org/x/mobile/cmd/gomobile@latest
fi

if [ -f "$GOMOBILE" ]; then
    GOMOBILE_CMD="$GOMOBILE"
elif command -v gomobile &>/dev/null; then
    GOMOBILE_CMD="gomobile"
else
    echo -e "${RED}Error: gomobile not found${NC}"
    echo "Install with: go install golang.org/x/mobile/cmd/gomobile@latest"
    exit 1
fi

echo -e "${GREEN}Using gomobile: $GOMOBILE_CMD${NC}"

# Check for Android SDK
if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
    # Try common locations
    if [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    else
        echo -e "${RED}Error: ANDROID_HOME or ANDROID_SDK_ROOT not set${NC}"
        echo "Please set ANDROID_HOME to your Android SDK location"
        exit 1
    fi
fi

ANDROID_SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
echo -e "${GREEN}Using Android SDK: $ANDROID_SDK${NC}"

# Initialize gomobile if needed
echo -e "${BLUE}Initializing gomobile...${NC}"
$GOMOBILE_CMD init || true

# Build the Go mobile library
echo -e "${BLUE}Building Go mobile library...${NC}"
cd "$PROJECT_ROOT"

# Create libs directory
mkdir -p "$SCRIPT_DIR/app/libs"

# Build AAR file
$GOMOBILE_CMD bind \
    -target=android \
    -androidapi=24 \
    -o "$SCRIPT_DIR/app/libs/mobile.aar" \
    ./dnstt-client/mobile

if [ -f "$SCRIPT_DIR/app/libs/mobile.aar" ]; then
    echo -e "${GREEN}Go library built: app/libs/mobile.aar${NC}"
else
    echo -e "${RED}Failed to build Go library${NC}"
    exit 1
fi

# Build Android app
echo -e "${BLUE}Building Android app...${NC}"
cd "$SCRIPT_DIR"

# Use gradle wrapper if available, otherwise use gradle
if [ -f "./gradlew" ]; then
    ./gradlew assembleRelease
else
    echo -e "${BLUE}Gradle wrapper not found, creating...${NC}"
    gradle wrapper --gradle-version 8.2
    ./gradlew assembleRelease
fi

# Copy APK to output
if [ -f "app/build/outputs/apk/release/app-release-unsigned.apk" ]; then
    cp "app/build/outputs/apk/release/app-release-unsigned.apk" "dnstt-client.apk"
    echo -e "${GREEN}Build complete: dnstt-client.apk${NC}"
elif [ -f "app/build/outputs/apk/debug/app-debug.apk" ]; then
    cp "app/build/outputs/apk/debug/app-debug.apk" "dnstt-client.apk"
    echo -e "${GREEN}Build complete: dnstt-client.apk${NC}"
else
    echo -e "${BLUE}Building debug APK...${NC}"
    ./gradlew assembleDebug
    cp "app/build/outputs/apk/debug/app-debug.apk" "dnstt-client.apk"
    echo -e "${GREEN}Build complete: dnstt-client.apk (debug)${NC}"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
echo ""
echo "To install on a connected device:"
echo "  adb install dnstt-client.apk"

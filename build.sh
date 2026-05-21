#!/bin/bash

BINARY_NAME="wazuh-json-transformer"
SOURCE_SCRIPT="wazuh-json-transformer.py"

rm -rf binaries

clean_build() {
    rm -rf build
    rm -rf dist
    rm -rf "$BINARY_NAME.spec"
    rm -rf wazuh-venv
}

build_for_arch() {
    clean_build

    local BUILD_ARCH=$1
    echo "Building for $BUILD_ARCH architecture..."

    if [[ "$BUILD_ARCH" == "arm64" ]]; then
        ARCH_CMD=""
        PYTHON_CMD="/opt/homebrew/bin/python3"
        BREW_CMD="/opt/homebrew/bin/brew"
    else
        ARCH_CMD="arch -x86_64"
        PYTHON_CMD="/usr/local/bin/python3"
        BREW_CMD="/usr/local/bin/brew"
    fi

    if [ ! -f "$BREW_CMD" ]; then
        echo "WARNING: installing Homebrew at $BREW_CMD"
        $ARCH_CMD /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    $ARCH_CMD brew install python

    $ARCH_CMD $PYTHON_CMD -m venv wazuh-venv
    source wazuh-venv/bin/activate

    $ARCH_CMD pip install --upgrade pip
    $ARCH_CMD pip install --upgrade pyinstaller

    $ARCH_CMD pyinstaller --clean --strip --optimize 2 \
        --onefile \
        --name "$BINARY_NAME" \
        "$SOURCE_SCRIPT"

    deactivate

    mkdir -p "binaries/$BUILD_ARCH"
    cp "dist/$BINARY_NAME" "binaries/$BUILD_ARCH/$BINARY_NAME"

    BINARY_PATH="binaries/$BUILD_ARCH/$BINARY_NAME"
    if [ -f "$BINARY_PATH" ]; then
        BUILT_ARCH=$(file "$BINARY_PATH" | grep -o "x86_64\|arm64")
        echo "Built binary architecture: $BUILT_ARCH"
    fi

    echo "Build for $BUILD_ARCH completed."

    clean_build
}

build_for_arch "arm64"
build_for_arch "x86_64"

echo "Build completed."

./package.sh
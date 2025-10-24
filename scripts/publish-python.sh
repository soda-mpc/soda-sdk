#!/bin/bash

# Soda Python SDK Publishing Script
# This script helps you test and publish the Python SDK to PyPI

set -e  # Exit on any error

echo "🐍 Soda Python SDK Publishing Helper"
echo "====================================="

# Check if we're in the right directory
if [ ! -f "setup.py" ]; then
    echo "❌ Error: setup.py not found. Please run this script from the project root."
    exit 1
fi

# Function to show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  test-local    - Test the package locally without publishing"
    echo "  publish-test  - Publish to TestPyPI"
    echo "  publish-pypi  - Publish to PyPI"
    echo "  check-setup   - Check if everything is ready for publishing"
    echo "  install-dev   - Install package in development mode"
    echo "  setup-venv    - Set up virtual environment only"
    echo "  cleanup       - Clean up build artifacts and virtual environment"
    echo ""
}

# Function to create and activate virtual environment
setup_venv() {
    echo "🔧 Setting up virtual environment..."
    
    # Remove existing venv if it exists
    if [ -d "venv" ]; then
        echo "🧹 Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Create new virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install build tools
    echo "📦 Installing build tools..."
    pip install build twine wheel
    
    # Install package dependencies
    echo "📦 Installing package dependencies..."
    pip install -r requirements.txt
    
    echo "✅ Virtual environment ready!"
}

# Function to check setup
check_setup() {
    echo "🔍 Checking Python setup..."
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python3 not found. Please install Python 3.7+"
        return 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo "✅ Python version: $PYTHON_VERSION"
    
    # Setup virtual environment
    setup_venv
    
    # Check if tests pass
    echo "🧪 Running Python tests..."
    cd python/soda_python_sdk
    if python -m unittest test.py -v -k "TestMpcHelper"; then
        echo "✅ All Python tests passed"
    else
        echo "❌ Python tests failed. Please fix tests before publishing."
        cd ../..
        return 1
    fi
    cd ../..
    
    # Check if package builds
    echo "📦 Testing package build..."
    if python -m build; then
        echo "✅ Package builds successfully"
    else
        echo "❌ Package build failed. Please fix build issues."
        return 1
    fi
    
    echo "✅ Setup check complete!"
    return 0
}

# Function to test locally
test_local() {
    echo "🧪 Testing Python package locally..."
    
    # Setup virtual environment
    setup_venv
    
    # Build the package
    echo "📦 Building package..."
    python -m build
    
    # Install the package locally
    echo "🔧 Installing package locally..."
    pip install dist/*.whl --force-reinstall
    
    # Test the package
    echo "🧪 Testing package functionality..."
    python -c "
from soda_python_sdk import generate_aes_key, prepare_IT, BLOCK_SIZE
key = generate_aes_key()
print('✅ Python SDK working! Generated key length:', len(key))
print('✅ BLOCK_SIZE constant:', BLOCK_SIZE)
"
    
    echo "✅ Local test completed successfully!"
}

# Function to install in development mode
install_dev() {
    echo "🔧 Installing package in development mode..."
    
    # Setup virtual environment
    setup_venv
    
    cd python
    pip install -e .
    cd ..
    
    echo "✅ Package installed in development mode!"
    echo "You can now import and test the package:"
    echo "source venv/bin/activate && python -c \"from soda_python_sdk import generate_aes_key; print(generate_aes_key())\""
}

# Function to publish to TestPyPI
publish_test() {
    echo "🚀 Publishing to TestPyPI..."
    
    # Check setup first
    if ! check_setup; then
        exit 1
    fi
    
    # Create a test version
    echo "📝 Creating test version..."
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    CURRENT_VERSION=$(python -c "import re; print(re.search(r'version=[\'\"]([^\'\"]*)[\'\"]', open('setup.py').read()).group(1))")
    NEW_VERSION="${CURRENT_VERSION}.dev${TIMESTAMP}"
    sed -i.bak "s/version='[^']*'/version='$NEW_VERSION'/" setup.py
    echo "Updated version to: $NEW_VERSION"
    
    # Build the package
    echo "📦 Building package..."
    python -m build
    
    # Verify package
    echo "🔍 Verifying package..."
    python -m twine check dist/*
    
    # Publish to TestPyPI
    echo "📤 Publishing to TestPyPI..."
    python -m twine upload --repository testpypi dist/*
    
    # Restore original version
    mv setup.py.bak setup.py
    
    echo "✅ Successfully published to TestPyPI!"
    echo "📦 Install with: pip install --index-url https://test.pypi.org/simple/ soda-sdk"
}

# Function to publish to PyPI
publish_pypi() {
    echo "🚀 Publishing to PyPI..."
    
    if ! check_setup; then
        exit 1
    fi
    
    # Build the package
    echo "📦 Building package..."
    python -m build
    
    # Verify package
    echo "🔍 Verifying package..."
    python -m twine check dist/*
    
    # Publish to PyPI
    echo "📤 Publishing to PyPI..."
    python -m twine upload dist/*
    
    echo "✅ Successfully published to PyPI!"
    echo "📦 Install with: pip install soda-sdk"
}

# Function to clean up
cleanup() {
    echo "🧹 Cleaning up..."
    rm -rf dist/
    rm -rf build/
    rm -rf *.egg-info/
    rm -rf venv/
    rm -f setup.py.bak
    echo "✅ Cleanup complete!"
}

# Main script logic
case "${1:-}" in
    "test-local")
        test_local
        cleanup
        ;;
    "publish-test")
        publish_test
        cleanup
        ;;
    "publish-pypi")
        publish_pypi
        cleanup
        ;;
    "check-setup")
        check_setup
        ;;
    "install-dev")
        install_dev
        ;;
    "setup-venv")
        setup_venv
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

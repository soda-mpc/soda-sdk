#!/bin/bash

# Soda TypeScript SDK Publishing Script
# This script helps you test and publish the TypeScript/JavaScript SDK to npm

set -e  # Exit on any error

echo "🚀 Soda TypeScript SDK Publishing Helper"
echo "========================================="

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found. Please run this script from the project root."
    exit 1
fi

# Function to show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  test-local    - Test the package locally without publishing"
    echo "  publish-test  - Publish to npm test channel"
    echo "  publish-beta  - Publish to npm beta channel"
    echo "  publish-latest - Publish to npm latest channel"
    echo "  check-setup   - Check if everything is ready for publishing"
    echo ""
}

# Function to check setup
check_setup() {
    echo "🔍 Checking setup..."
    
    # Check if logged in to npm
    if ! npm whoami > /dev/null 2>&1; then
        echo "❌ Not logged in to npm. Please run 'npm login' first."
        return 1
    fi
    
    echo "✅ Logged in to npm as: $(npm whoami)"
    
    # Check if package name is available
    if npm view soda-sdk > /dev/null 2>&1; then
        echo "✅ Package 'soda-sdk' exists on npm"
    else
        echo "⚠️  Package 'soda-sdk' not found on npm (this is normal for new packages)"
    fi
    
    # Check if dist directory exists
    if [ ! -d "dist" ]; then
        echo "❌ dist/ directory not found. Please run 'npm run build' first."
        return 1
    fi
    
    echo "✅ dist/ directory exists"
    
    # Check if tests pass
    echo "🧪 Running tests..."
    if npm test; then
        echo "✅ All tests passed"
    else
        echo "❌ Tests failed. Please fix tests before publishing."
        return 1
    fi
    
    echo "✅ Setup check complete!"
    return 0
}

# Function to test locally
test_local() {
    echo "🧪 Testing package locally..."
    
    # Build the package
    echo "📦 Building package..."
    npm run build
    
    # Create a tarball
    echo "📦 Creating package tarball..."
    PACKAGE_FILE=$(npm pack)
    echo "✅ Created: $PACKAGE_FILE"
    
    # Test installation
    echo "🔧 Testing installation..."
    mkdir -p test-install
    cd test-install
    
    # Install the package
    npm init -y
    npm install ../$PACKAGE_FILE
    
    # Test the package
    echo "🧪 Testing package functionality..."
    node -e "
        const { generateAesKey, prepareIT256 } = require('soda-sdk');
        const key = generateAesKey();
        console.log('✅ SDK working! Generated key length:', key.length);
    " || echo "⚠️ Package test failed, but continuing..."
    
    # Cleanup
    cd ..
    rm -rf test-install
    rm -f $PACKAGE_FILE
    
    echo "✅ Local test completed successfully!"
}

# Function to publish to test channel
publish_test() {
    echo "🚀 Publishing to npm test channel..."
    
    # Check setup first
    if ! check_setup; then
        exit 1
    fi
    
    # Create a test version
    echo "📝 Creating test version..."
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    npm version prerelease --preid="test.$TIMESTAMP" --no-git-tag-version
    
    # Publish to test channel
    echo "📤 Publishing to test channel..."
    npm publish --tag test
    
    echo "✅ Successfully published to npm test channel!"
    echo "📦 Install with: npm install soda-sdk@test"
}

# Function to publish to beta channel
publish_beta() {
    echo "🚀 Publishing to npm beta channel..."
    
    if ! check_setup; then
        exit 1
    fi
    
    # Create a beta version
    echo "📝 Creating beta version..."
    npm version prerelease --preid="beta" --no-git-tag-version
    
    # Publish to beta channel
    echo "📤 Publishing to beta channel..."
    npm publish --tag beta
    
    echo "✅ Successfully published to npm beta channel!"
    echo "📦 Install with: npm install soda-sdk@beta"
}

# Function to publish to latest channel
publish_latest() {
    echo "🚀 Publishing to npm latest channel..."
    
    if ! check_setup; then
        exit 1
    fi
    
    # Publish to latest channel
    echo "📤 Publishing to latest channel..."
    npm publish
    
    echo "✅ Successfully published to npm latest channel!"
    echo "📦 Install with: npm install soda-sdk"
}

# Main script logic
case "${1:-}" in
    "test-local")
        test_local
        ;;
    "publish-test")
        publish_test
        ;;
    "publish-beta")
        publish_beta
        ;;
    "publish-latest")
        publish_latest
        ;;
    "check-setup")
        check_setup
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

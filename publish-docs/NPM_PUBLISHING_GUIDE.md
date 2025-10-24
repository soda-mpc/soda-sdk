# 🚀 npm Publishing Guide for Soda SDK

## 🔐 Setting up npm 2FA for GitHub Actions

### **Option 1: Access Tokens (Recommended)**

This is the most secure and widely used approach for CI/CD.

#### Step 1: Create npm Access Token

1. **Login to npm**:
   ```bash
   npm login
   ```

2. **Enable 2FA on your npm account**:
   ```bash
   npm profile enable-2fa auth-and-writes
   ```

3. **Create Access Token**:
   - Go to [npm Access Tokens](https://www.npmjs.com/settings/tokens)
   - Click "Generate New Token"
   - Select "Automation" token type
   - Copy the token (starts with `npm_`)

#### Step 2: Add Token to GitHub Secrets

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `NPM_TOKEN`
5. Value: Your npm access token (e.g., `npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)

### **Option 2: OIDC (OpenID Connect) - Advanced**

For organizations requiring OIDC authentication:

```yaml
- name: Publish to npm (using OIDC)
  uses: actions/setup-node@v4
  with:
    node-version: '18'
    registry-url: 'https://registry.npmjs.org'
    scope: '@your-org'  # If using scoped packages
  id: setup-node

- name: Publish to npm
  run: npm publish
  env:
    NODE_AUTH_TOKEN: ${{ steps.setup-node.outputs.registry-token }}
```

---

## 📦 Publishing Workflows

### **1. Manual Publishing (Workflow Dispatch)**

Trigger manually from GitHub Actions tab:

```bash
# In GitHub Actions tab:
# 1. Click "Publish to npm"
# 2. Click "Run workflow"
# 3. Select version: "1.0.0" or "patch"/"minor"/"major"
# 4. Select channel: "test", "beta", "alpha", or "latest"
```

### **2. Tag-based Publishing**

Create and push a version tag:

```bash
# Create and push a tag
git tag v1.0.0
git push origin v1.0.0

# This will automatically trigger publishing to 'latest' channel
```

### **3. Automatic Test Publishing**

Push to `testnet` branch:

```bash
git checkout testnet
git push origin testnet

# This will automatically publish to 'test' channel
```

---

## 🏷️ Version Management

### **Version Channels**

| Channel | Usage | Command |
|---------|-------|---------|
| `latest` | Production releases | `npm install soda-sdk` |
| `test` | Testing/development | `npm install soda-sdk@test` |
| `beta` | Beta releases | `npm install soda-sdk@beta` |
| `alpha` | Alpha releases | `npm install soda-sdk@alpha` |

### **Version Bumping**

```bash
# Patch version (0.0.2 → 0.0.3)
npm version patch

# Minor version (0.0.2 → 0.1.0)
npm version minor

# Major version (0.0.2 → 1.0.0)
npm version major

# Prerelease (0.0.2 → 0.0.3-0)
npm version prerelease
```

---

## 🔧 Configuration Files

### **package.json Updates**

Make sure your `package.json` has:

```json
{
  "name": "soda-sdk",
  "version": "0.0.2",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": [
    "dist/",
    "README.md",
    "LICENSE"
  ],
  "publishConfig": {
    "access": "public"
  },
  "scripts": {
    "build": "tsc",
    "test:ts": "jest",
    "test:js": "mocha --require esm js/test.mjs",
    "prepublishOnly": "npm run build && npm test"
  }
}
```

### **npmrc Configuration**

Create `.npmrc` file (optional):

```
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

---

## 🧪 Testing the Publishing

### **1. Test Locally**

```bash
# Build the package
npm run build

# Test the package locally
npm pack
# This creates a .tgz file you can test

# Install locally for testing
npm install ./soda-sdk-0.0.2.tgz
```

### **2. Test on npm Test Channel**

```bash
# Publish to test channel
npm publish --tag test

# Install from test channel
npm install soda-sdk@test
```

### **3. Verify Installation**

```typescript
import { generateAesKey, prepareIT256 } from 'soda-sdk';

// Test the functions
const key = generateAesKey();
console.log('SDK working:', key.length === 16);
```

---

## 🚨 Troubleshooting

### **Common Issues**

1. **"npm ERR! 403 Forbidden"**
   - Check if NPM_TOKEN is correctly set
   - Verify token has publish permissions
   - Ensure package name is available

2. **"npm ERR! 401 Unauthorized"**
   - Token might be expired
   - Check if 2FA is properly configured
   - Verify token scope

3. **"npm ERR! 400 Bad Request"**
   - Package name might be taken
   - Version might already exist
   - Check package.json format

### **Debug Commands**

```bash
# Check npm configuration
npm config list

# Check authentication
npm whoami

# Check package info
npm view soda-sdk

# Check available versions
npm view soda-sdk versions --json
```

---

## 📋 Pre-Publishing Checklist

- [ ] All tests passing (`npm test`)
- [ ] Build successful (`npm run build`)
- [ ] Version updated in package.json
- [ ] CHANGELOG.md updated
- [ ] README.md updated
- [ ] NPM_TOKEN set in GitHub Secrets
- [ ] Package name available on npm
- [ ] No sensitive data in package

---

## 🎯 Quick Start

1. **Set up NPM_TOKEN** in GitHub Secrets
2. **Push to testnet branch** for test publishing
3. **Create version tag** for production publishing
4. **Use manual workflow** for specific versions

```bash
# Quick test publishing
git checkout testnet
git push origin testnet

# Quick production publishing
git tag v1.0.0
git push origin v1.0.0
```

---

## 🔗 Useful Links

- [npm Access Tokens](https://www.npmjs.com/settings/tokens)
- [npm Publishing Guide](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [npm 2FA Documentation](https://docs.npmjs.com/about-two-factor-authentication)

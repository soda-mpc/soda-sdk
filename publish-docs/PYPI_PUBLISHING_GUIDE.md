# 🐍 PyPI Publishing Guide for Soda Python SDK

## 🔐 Setting up PyPI Authentication for GitHub Actions

### **Option 1: API Tokens (Recommended)**

This is the most secure and widely used approach for CI/CD.

#### Step 1: Create PyPI API Token

1. **Login to PyPI**:
   ```bash
   pip install twine
   twine upload --help  # This will prompt for login
   ```

2. **Create API Token**:
   - Go to [PyPI Account Settings](https://pypi.org/manage/account/)
   - Click "Add API token"
   - Give it a name like "GitHub Actions"
   - Select scope: "Entire account" or "Specific projects"
   - Copy the token (starts with `pypi-`)

3. **For TestPyPI** (optional):
   - Go to [TestPyPI Account Settings](https://test.pypi.org/manage/account/)
   - Create a separate token for testing

#### Step 2: Add Token to GitHub Secrets

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `PYPI_API_TOKEN`
5. Value: Your PyPI API token (e.g., `pypi_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)

### **Option 2: OIDC (OpenID Connect) - Advanced**

For organizations requiring OIDC authentication:

```yaml
- name: Publish to PyPI (using OIDC)
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    user: __token__
    password: ${{ secrets.PYPI_API_TOKEN }}
    repository_url: https://upload.pypi.org/legacy/
```

---

## 📦 Publishing Workflows

### **1. Manual Publishing (Workflow Dispatch)**

Trigger manually from GitHub Actions tab:

```bash
# In GitHub Actions tab:
# 1. Click "Publish Python Package to PyPI"
# 2. Click "Run workflow"
# 3. Select version: "0.1.0" or "patch"/"minor"/"major"
# 4. Select channel: "testpypi" or "pypi"
```

### **2. Automatic Test Publishing**

Push to `python-dev` branch:

```bash
git checkout python-dev
git push origin python-dev

# This will automatically publish to TestPyPI
```

### **3. Local Publishing**

Use the provided script:

```bash
# Test locally first
./scripts/publish-python.sh test-local

# Publish to TestPyPI
./scripts/publish-python.sh publish-test

# Publish to PyPI
./scripts/publish-python.sh publish-pypi
```

---

## 🏷️ Version Management

### **Version Channels**

| Channel | Usage | Install Command |
|---------|-------|-----------------|
| `pypi` | Production releases | `pip install soda-sdk` |
| `testpypi` | Testing/development | `pip install --index-url https://test.pypi.org/simple/ soda-sdk` |

### **Version Bumping**

```bash
# Patch version (0.0.3 → 0.0.4)
python3 -c "
import re
with open('setup.py', 'r') as f:
    content = f.read()
current = re.search(r'version=[\'\"]([^\'\"]*)[\'\"]', content).group(1)
print(f'Current version: {current}')
"

# Update version in setup.py
sed -i "s/version='[^']*'/version='0.0.4'/" setup.py
```

---

## 🔧 Configuration Files

### **setup.py Updates**

The setup.py has been updated with:

```python
setup(
    name='soda-sdk',
    version='0.0.3',
    description='Cryptographic SDK for AES, RSA, ECDSA encryption and Soda Labs blockchain integration',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Soda Labs',
    author_email='meital@sodalabs.xyz',
    url='https://github.com/soda-mpc/soda-sdk',
    project_urls={
        'Homepage': 'https://github.com/soda-mpc/soda-sdk',
        'Bug Reports': 'https://github.com/soda-mpc/soda-sdk/issues',
        'Source': 'https://github.com/soda-mpc/soda-sdk',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Blockchain',
    ],
    python_requires='>=3.7',
    install_requires=[
        'pycryptodome>=3.10.0',
        'eth-keys>=0.3.3',
        'cryptography>=3.4.7',
        'web3==6.11.2',
    ],
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'black>=21.0',
            'flake8>=3.8',
            'mypy>=0.800',
        ],
        'test': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
        ],
    },
    keywords=[
        'cryptography',
        'aes',
        'rsa',
        'ecdsa',
        'blockchain',
        'sodalabs',
        'mpc',
        'garbled-circuits',
        'encryption',
        'privacy',
    ],
)
```

---

## 🧪 Testing the Publishing

### **1. Test Locally**

```bash
# Test the package locally
./scripts/publish-python.sh test-local

# Install in development mode
./scripts/publish-python.sh install-dev
```

### **2. Test on TestPyPI**

```bash
# Publish to TestPyPI
./scripts/publish-python.sh publish-test

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ soda-sdk
```

### **3. Verify Installation**

```python
from soda_python_sdk import generate_aes_key, prepare_IT, BLOCK_SIZE

# Test the functions
key = generate_aes_key()
print('SDK working! Generated key length:', len(key))
print('BLOCK_SIZE constant:', BLOCK_SIZE)
```

---

## 🚨 Troubleshooting

### **Common Issues**

1. **"HTTPError: 403 Client Error: Invalid or non-existent authentication information"**
   - Check if PYPI_API_TOKEN is correctly set
   - Verify token has upload permissions
   - Ensure token is not expired

2. **"HTTPError: 400 Client Error: File already exists"**
   - Version already exists on PyPI
   - Increment version number
   - Use TestPyPI for testing

3. **"ModuleNotFoundError: No module named 'build'"**
   - Install build tools: `pip install build twine wheel`

4. **"error: invalid command 'bdist_wheel'"**
   - Install wheel: `pip install wheel`

### **Debug Commands**

```bash
# Check Python version
python3 --version

# Check installed packages
pip3 list

# Check package build
python3 -m build

# Verify package
python3 -m twine check dist/*

# Test package installation
pip3 install dist/*.whl --force-reinstall
```

---

## 📋 Pre-Publishing Checklist

- [ ] All Python tests passing (`python3 -m unittest test.py -v`)
- [ ] Package builds successfully (`python3 -m build`)
- [ ] Version updated in setup.py
- [ ] README_PY.md updated
- [ ] PYPI_API_TOKEN set in GitHub Secrets
- [ ] Package name available on PyPI
- [ ] No sensitive data in package
- [ ] Dependencies properly specified

---

## 🎯 Quick Start

1. **Set up PYPI_API_TOKEN** in GitHub Secrets
2. **Test locally**:
   ```bash
   ./scripts/publish-python.sh check-setup
   ./scripts/publish-python.sh test-local
   ```
3. **Publish to TestPyPI**:
   ```bash
   ./scripts/publish-python.sh publish-test
   ```
4. **Publish to PyPI**:
   ```bash
   ./scripts/publish-python.sh publish-pypi
   ```

---

## 🔗 Useful Links

- [PyPI Account Settings](https://pypi.org/manage/account/)
- [TestPyPI Account Settings](https://test.pypi.org/manage/account/)
- [PyPI Publishing Guide](https://packaging.python.org/tutorials/packaging-projects/)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Python Packaging User Guide](https://packaging.python.org/)

---

## 📊 Package Information

- **Package Name**: `soda-sdk`
- **Current Version**: `0.0.3`
- **Python Requirements**: `>=3.7`
- **Dependencies**: `pycryptodome`, `eth-keys`, `cryptography`, `web3`
- **License**: MIT
- **Keywords**: cryptography, aes, rsa, ecdsa, blockchain, sodalabs

from setuptools import setup, find_packages
import os

# Read requirements from the requirements.txt file
def get_requirements():
    """Get requirements from requirements.txt file."""
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    with open(requirements_path, 'r') as f:
        requirements = f.read().strip().split('\n')
        # Filter out empty lines and comments
        requirements = [req.strip() for req in requirements if req.strip() and not req.strip().startswith('#')]
        return requirements

install_requires = get_requirements()

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README_PY.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Soda SDK - Cryptographic functions for Soda Labs blockchain"

setup(
    name='gcevm-sdk',
    version='0.0.5',
    packages=find_packages(where='python'),
    package_dir={'': 'python'},
    description='Soda SDK - Cryptographic functions for Soda Labs blockchain',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Soda Labs',
    author_email='meital@sodalabs.xyz',
    url='https://github.com/soda-mpc/soda-sdk',
    project_urls={
        'Homepage': 'https://github.com/soda-mpc/soda-sdk',
        'Bug Reports': 'https://github.com/soda-mpc/soda-sdk/issues',
        'Source': 'https://github.com/soda-mpc/soda-sdk',
        'Documentation': 'https://github.com/soda-mpc/soda-sdk#readme',
    },
    license='MIT',
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
    ],
    python_requires='>=3.7',
    install_requires=install_requires,
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
    include_package_data=True,
    zip_safe=False,
)

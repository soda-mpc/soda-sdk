from setuptools import setup, find_packages
import os

# Read requirements from the requirements.txt file
# Get the directory where setup.py is located
setup_dir = os.path.dirname(os.path.abspath(__file__))
requirements_path = os.path.join(setup_dir, 'requirements.txt')

if os.path.exists(requirements_path):
    with open(requirements_path) as f:
        install_requires = [line.strip() for line in f if line.strip() and not line.startswith('#')]
else:
    # Fallback if requirements.txt is not found
    install_requires = [
        'pycryptodome>=3.10.0',
        'eth-keys>=0.3.3',
        'cryptography>=3.4.7',
        'web3==6.11.2',
    ]

setup(
    name='soda-bubble-sdk',
    version='0.0.11',
    packages=find_packages(where='python'),  # Look for packages in the 'python' directory
    package_dir={'': 'python'},  # Maps the root package to the 'python' directory
    description='This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalities used for working with sodalabs blockchain.',
    long_description=(open(os.path.join(setup_dir, 'README_PY.md'), encoding='utf-8').read() 
                     if os.path.exists(os.path.join(setup_dir, 'README_PY.md')) 
                     else 'This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalities used for working with sodalabs blockchain.'),
    long_description_content_type='text/markdown',
    author='sodalabs',
    author_email='meital@sodalabs.xyz',
    url='https://github.com/soda-mpc/soda-sdk',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=install_requires,
)

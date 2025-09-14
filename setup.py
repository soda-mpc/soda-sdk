from setuptools import setup, find_packages

# Read requirements from the requirements.txt file
with open('requirements.txt') as f:
    install_requires = f.read().strip().split('\n')

setup(
    name='soda-sdk',
    version='0.0.1',
    packages=find_packages(where='python'),  # Look for packages in the 'python' directory
    package_dir={'': 'python'},  # Maps the root package to the 'python' directory
    description='This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalities used for working with sodalabs blockchain.',
    long_description=open('README_PY.md').read(),
    long_description_content_type='text/markdown',
    author='sodalabs',
    author_email='meital@sodalabs.xyz',
    url='https://github.com/soda-mpc/soda-sdk',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: MIT License'
    ],
    python_requires='>=3.6',
    install_requires=install_requires,
)

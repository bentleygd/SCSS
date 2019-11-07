import setuptools


with open('README.md', 'r') as l_desc:
    long_description = l_desc.read()

setuptools.setup(
    name='scss',
    version='0.0.1',
    author='Gabriel Bentley',
    author_email='no_email@no-domain.com',
    description='Secure Credential Storage Service',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bentleygd/scss",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU GPL v3.0",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

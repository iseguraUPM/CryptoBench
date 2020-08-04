# CryptoBench (HEncrypt suite)

This library is a work in progress suite to build **HEncrypt** a tunable dynamic encryption engine. The project compiles several external static and shared libraries.

## Installation

Before istall:

- To properly build the library, pull the submodules with:
`git submodule update --recursive`

    -  External Libraries: Google-test, OR-tools, CryptoPP, OpenSSL, Libgcrypt, Libgpg-error, Libsodium, WolfSSL, Botan

- Linux dependencies (tested in Debian and CentOS): `gettext texinfo transfig libtool ghostscript autotools-dev`

- Minimum version of [CMake 3.15](https://cmake.org/files/v3.15/cmake-3.15.0.tar.gz) required

To use:

    sh autogen.sh
    mkdir <build directory>
    cmake -B<build directory> .
    cd <build directory>
    make

*Note: The project is not configured for system installation. Must be run locally.*

## Tools

- **HEncrypt** library allows access to the dynamic encryption engine and a symple interface to use the encryption libraries mentioned above
- **CipherBenchmarkRunner** provides empircal data to run the engine
- **EngineBenchmarkRunner** measures the engine performance. See [engine readme](EngineBenchmarkRunner/README.md) for information on how to run the engine and its data dependencies.

When benchmarking refer to [the scripts](script/README.md) generated for the project.
# CryptoBench (HEncrypt suite)

This library is a work in progress suite to build **HEncrypt** a tunable dynamic encryption engine. The project compiles several external static
libraries.

## Installation

Before istall:

- To properly build the library, pull the submodules with:
`git submodule update --recursive`

    -  External Libraries: Google-test, OR-tools, CryptoPP, OpenSSL, Libgcrypt, Libgpg-error, Libsodium, WolfSSL, Botan

- Linux dependencies: gettext texinfo transfig libtool ghostscript autotools-dev

- Minimum of CMake 3.15: https://cmake.org/files/v3.15/cmake-3.15.0.tar.gz

To install:

    sh autogen.sh
    mkdir <build directory>
    cmake -B<build directory> .
    cd <build directory>
    make

`The system is not configured for system installation. Must be run locally.`

## Tools

- **HEncrypt** library allows access to the dynamic encryption engine and a symple interface to use the encryption libraries mentioned above
- **CipherBenchmarkRunner** provides empircal data to run the engine
- **EngineBenchmarkRunner** measures the engine performance
- `script/query.py` generates the required cipher seed input for the engine

`Aside from the cipher seed, hencrypt requires also a system profile file which is a text file following the format by line:`

    <drive identifier> <storage_path (ending in /)> <drive pace metric>
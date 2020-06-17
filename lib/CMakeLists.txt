set(SYSTEM_OPENSSL OFF CACHE BOOL "Use system OpenSSL" FORCE)
set(BUILD_OPENSSL ON CACHE BOOL "Build own OpenSSL" FORCE)
set(OPENSSL_BRANCH OpenSSL_1_1_1d CACHE STRING "OpenSSL Git branch" FORCE)
set(OPENSSL_BUILD_VERSION 1.1.1d CACHE STRING "OpenSSL version" FORCE)

if (HENCRYPT_NO_OPTS)
    set(OPENSSL_NO_OPTS ON)
    set(CRYPTOPP_NO_OPTS ON)
    set(BOTAN_NO_OPTS ON)
    set(WOLFSSL_NO_OPTS ON)
    set(GCRYPT_NO_OPTS ON)
    set(LIBSODIUM_NO_OPTS ON)
endif()

add_subdirectory(OpenSSL-CMake)

add_subdirectory(cryptopp-8.2)

add_subdirectory(libsodium-1.0.18)

add_subdirectory(libgpg-error-1.37)

add_subdirectory(libgcrypt-1.8.5)

add_subdirectory(Botan-2.13.0)

add_subdirectory(wolfSSL-4.3.0)

add_subdirectory(Google_test)
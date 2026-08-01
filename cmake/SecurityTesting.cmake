set(
    SECURECORE_SANITIZER
    "none"
    CACHE STRING
    "Runtime sanitizer: none, address, undefined, address-undefined, or thread"
)

set_property(
    CACHE SECURECORE_SANITIZER
    PROPERTY STRINGS
        none
        address
        undefined
        address-undefined
        thread
)

option(
    SECURECORE_BUILD_FUZZERS
    "Build Clang/libFuzzer parser targets"
    OFF
)

set(_securecore_supported_sanitizer_compiler FALSE)
if(
    CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR
    CMAKE_CXX_COMPILER_ID MATCHES "Clang"
)
    set(_securecore_supported_sanitizer_compiler TRUE)
endif()

if(NOT SECURECORE_SANITIZER STREQUAL "none")
    if(NOT _securecore_supported_sanitizer_compiler)
        message(FATAL_ERROR
            "SECURECORE_SANITIZER requires GCC or Clang"
        )
    endif()

    set(_securecore_sanitizer_flags)

    if(SECURECORE_SANITIZER STREQUAL "address")
        list(APPEND _securecore_sanitizer_flags
            -fsanitize=address
        )
    elseif(SECURECORE_SANITIZER STREQUAL "undefined")
        list(APPEND _securecore_sanitizer_flags
            -fsanitize=undefined
            -fno-sanitize-recover=undefined
        )
    elseif(SECURECORE_SANITIZER STREQUAL "address-undefined")
        list(APPEND _securecore_sanitizer_flags
            -fsanitize=address,undefined
            -fno-sanitize-recover=undefined
        )
    elseif(SECURECORE_SANITIZER STREQUAL "thread")
        list(APPEND _securecore_sanitizer_flags
            -fsanitize=thread
        )
    else()
        message(FATAL_ERROR
            "Invalid SECURECORE_SANITIZER='${SECURECORE_SANITIZER}'"
        )
    endif()

    list(APPEND _securecore_sanitizer_flags
        -fno-omit-frame-pointer
        -fno-optimize-sibling-calls
    )

    add_compile_options(
        ${_securecore_sanitizer_flags}
    )

    add_link_options(
        ${_securecore_sanitizer_flags}
    )

    message(STATUS
        "SecureCore sanitizer: ${SECURECORE_SANITIZER}"
    )
endif()

if(SECURECORE_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "SECURECORE_BUILD_FUZZERS requires Clang with libFuzzer"
        )
    endif()

    if(SECURECORE_SANITIZER STREQUAL "thread")
        message(FATAL_ERROR
            "libFuzzer targets cannot be combined with ThreadSanitizer"
        )
    endif()
endif()

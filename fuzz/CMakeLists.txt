function(securecore_add_fuzzer target source)
    add_executable(
        ${target}
        ${source}
    )

    target_link_libraries(
        ${target}
        PRIVATE
            securecore
    )

    target_compile_options(
        ${target}
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -fsanitize=fuzzer
    )

    target_link_options(
        ${target}
        PRIVATE
            -fsanitize=fuzzer
    )

    set_target_properties(
        ${target}
        PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY
                "${CMAKE_BINARY_DIR}/fuzzers"
    )
endfunction()

securecore_add_fuzzer(
    securecore-fuzz-query
    fuzz_query.cpp
)

securecore_add_fuzzer(
    securecore-fuzz-proxy-headers
    fuzz_proxy_headers.cpp
)

securecore_add_fuzzer(
    securecore-fuzz-cors
    fuzz_cors.cpp
)

securecore_add_fuzzer(
    securecore-fuzz-json-validation
    fuzz_json_validation.cpp
)

securecore_add_fuzzer(
    securecore-fuzz-request-id
    fuzz_request_id.cpp
)

securecore_add_fuzzer(
    securecore-fuzz-router
    fuzz_router.cpp
)

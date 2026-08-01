set(
    SECURECORE_VERSION_OVERRIDE
    ""
    CACHE STRING
    "Override the SecureCore version embedded in binaries"
)

set(
    SECURECORE_GIT_COMMIT
    ""
    CACHE STRING
    "Git commit embedded in SecureCore binaries"
)

function(securecore_configure_version)
    if(SECURECORE_VERSION_OVERRIDE)
        set(_securecore_version "${SECURECORE_VERSION_OVERRIDE}")
    else()
        set(_securecore_version "${PROJECT_VERSION}")
    endif()

    string(REGEX REPLACE "^v" "" _securecore_version "${_securecore_version}")

    if(NOT _securecore_version MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")
        message(FATAL_ERROR
            "Invalid SecureCore version: '${_securecore_version}'"
        )
    endif()

    set(_securecore_git_commit "${SECURECORE_GIT_COMMIT}")
    if(NOT _securecore_git_commit)
        find_package(Git QUIET)
        if(Git_FOUND)
            execute_process(
                COMMAND
                    ${GIT_EXECUTABLE}
                    rev-parse
                    --short=12
                    HEAD
                WORKING_DIRECTORY
                    "${CMAKE_CURRENT_SOURCE_DIR}"
                RESULT_VARIABLE
                    _securecore_git_result
                OUTPUT_VARIABLE
                    _securecore_git_output
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
            )

            if(_securecore_git_result EQUAL 0)
                set(_securecore_git_commit "${_securecore_git_output}")
            endif()
        endif()
    endif()

    if(NOT _securecore_git_commit)
        set(_securecore_git_commit "unknown")
    endif()

    if(NOT _securecore_git_commit MATCHES "^[0-9A-Za-z._-]+$")
        message(FATAL_ERROR
            "Invalid SECURECORE_GIT_COMMIT: '${_securecore_git_commit}'"
        )
    endif()

    set(SECURECORE_VERSION_STRING "${_securecore_version}")
    set(SECURECORE_GIT_COMMIT_STRING "${_securecore_git_commit}")

    file(MAKE_DIRECTORY
        "${CMAKE_CURRENT_BINARY_DIR}/generated/secure"
    )

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/securecore_version.hpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/secure/version.hpp"
        @ONLY
    )

    set(SECURECORE_VERSION_STRING "${_securecore_version}" PARENT_SCOPE)
    set(SECURECORE_GIT_COMMIT_STRING "${_securecore_git_commit}" PARENT_SCOPE)
endfunction()

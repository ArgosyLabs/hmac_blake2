cmake_minimum_required(VERSION 3.1)

set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
		STRING "Choose the type of build." FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

project(hmac_blake2)

set(${PROJECT_NAME}_OBJECTS
	hmac_blake2b
	hmac_blake2s
)

set(${PROJECT_NAME}_LIBRARIES
	b2
)

set(${PROJECT_NAME}_HEADERS
	)
list(APPEND ${PROJECT_NAME}_HEADERS "${${PROJECT_NAME}_OBJECTS}")

set(${PROJECT_NAME}_TESTS
	)

add_library(hmac_blake2 OBJECT)
foreach(object ${${PROJECT_NAME}_OBJECTS})
	target_sources(hmac_blake2 PUBLIC ${object}.c)
endforeach(object)
set_property(TARGET hmac_blake2 PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(hmac_blake2-static STATIC $<TARGET_OBJECTS:hmac_blake2>)
set_target_properties(hmac_blake2-static PROPERTIES OUTPUT_NAME hmac_blake2)
add_library(hmac_blake2-shared SHARED $<TARGET_OBJECTS:hmac_blake2>)
set_target_properties(hmac_blake2-shared PROPERTIES OUTPUT_NAME hmac_blake2 SOVERSION 0 VERSION 0.0.0)

foreach(library ${${PROJECT_NAME}_LIBRARIES})
	find_library(${library}_LIBRARY ${library})
	if (${library}_LIBRARY)
		target_link_libraries(hmac_blake2-static ${${library}_LIBRARY})
		target_link_libraries(hmac_blake2-shared ${${library}_LIBRARY})
	else()
		message(FATAL_ERROR "Missing: " ${library})
	endif()
endforeach(library)

install(TARGETS
	hmac_blake2-static
	hmac_blake2-shared
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
)

foreach(header ${${PROJECT_NAME}_HEADERS})
	install(FILES ${header}.h DESTINATION "include")
endforeach(header)

enable_testing()
add_custom_target(all_tests)
foreach(test ${${PROJECT_NAME}_TESTS})
	add_executable(${test} EXCLUDE_FROM_ALL ${test}.c)
	add_test(NAME ${test} COMMAND $<TARGET_FILE:${test}>)
	add_dependencies(all_tests ${test})
endforeach(test)
build_command(CTEST_CUSTOM_PRE_TEST TARGET all_tests)
string(CONFIGURE \"@CTEST_CUSTOM_PRE_TEST@\" CTEST_CUSTOM_PRE_TEST_QUOTED ESCAPE_QUOTES)
file(WRITE "${CMAKE_BINARY_DIR}/CTestCustom.cmake" "set(CTEST_CUSTOM_PRE_TEST ${CTEST_CUSTOM_PRE_TEST_QUOTED})" "\n")

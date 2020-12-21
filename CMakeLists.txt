cmake_minimum_required (VERSION 3.8)
project ("Test 323")

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd ")
# set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /WX")

find_package(cryptopp CONFIG REQUIRED)
find_path(BOOST_LOCKFREE_INCLUDE_DIRS "boost/lockfree/")
find_path(BOOST_MULTI_INDEX_INCLUDE_DIRS "boost/multi_index/")
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/exe")

set(
	SBH_COMPILE_FLAGS
	"/MP"
	"/WX"
)


set(
	TARGET_EXE
		SearchByHash
)
add_executable (
	${TARGET_EXE}
		"SearchByHash.cpp" 
)
target_link_libraries(
 	${TARGET_EXE} PRIVATE
	 	cryptopp-static
)
target_include_directories(
	${TARGET_EXE} PRIVATE
		${BOOST_LOCKFREE_INCLUDE_DIRS}
		${BOOST_MULTI_INDEX_INCLUDE_DIRS}
)
set_target_properties(${TARGET_EXE} PROPERTIES COMPILE_OPTIONS "${SBH_COMPILE_FLAGS}")
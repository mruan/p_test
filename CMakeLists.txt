cmake_minimum_required (VERSION 2.7)
project (paillier_test)

#set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
#find_package(GMP REQUIRED)

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
#set(CMAKE_BUILD_TYPE DEBUG)

include_directories(/usr/local/include/)
link_directories(/usr/local/lib/)

add_executable(ut02 ut02.c)
target_link_libraries(ut02 paillier gmp)

#if (GMP_FOUND)
#  include_directories(${BZIP_INCLUDE_DIRS})
#  target_link_libraries(test_01 paillier ${GMP_LIBRARY})
#endif (GMP_FOUND)

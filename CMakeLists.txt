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

add_executable(ut03 ut03.c)
target_link_libraries(ut03 paillier gmp)

add_executable(ut04 ut04.c)

add_executable(ut05 ut05.c)
target_link_libraries(ut05 paillier gmp)

add_executable(ut06 ut06.c)
target_link_libraries(ut06 paillier gmp)

add_executable(ut07 ut07.c)
target_link_libraries(ut07 paillier gmp)

#add_executable(eg01 eg01.c)
#target_link_libraries(eg01 paillier gmp)

add_executable(ut08 ut08.c utils.c)
target_link_libraries(ut08 paillier gmp)

add_executable(ut09 ut09.c)
target_link_libraries(ut09 paillier gmp)

add_executable(ut10 ut10.c utils.c)
target_link_libraries(ut10 paillier gmp)

add_executable(ut11 ut11.c utils.c)
target_link_libraries(ut11 paillier gmp)

#if (GMP_FOUND)
#  include_directories(${BZIP_INCLUDE_DIRS})
#  target_link_libraries(test_01 paillier ${GMP_LIBRARY})
#endif (GMP_FOUND)

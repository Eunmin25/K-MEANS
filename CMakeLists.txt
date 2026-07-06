cmake_minimum_required (VERSION 3.5.1)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create OpenFHE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: OPENFHEpke_static.a, OPENFHEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(demo CXX)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE CONFIG REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif ()

set( CMAKE_CXX_FLAGS "${OpenFHE_CXX_FLAGS} -Wno-shift-op-parentheses" )

set(LOCAL_OPENFHE_SRC "${CMAKE_SOURCE_DIR}/openfhe-development-1.1.2/src")
if (EXISTS "${LOCAL_OPENFHE_SRC}/pke/include/openfhe.h")
    message(STATUS "Using bundled OpenFHE headers from ${LOCAL_OPENFHE_SRC}")
    include_directories(BEFORE
        ${LOCAL_OPENFHE_SRC}/pke/include
        ${LOCAL_OPENFHE_SRC}/core/include
        ${LOCAL_OPENFHE_SRC}/binfhe/include
    )
endif()

set(LOCAL_OPENFHE_LIBDIR "${CMAKE_SOURCE_DIR}/openfhe-development-1.1.2/build/lib")
if (EXISTS "${LOCAL_OPENFHE_LIBDIR}/libOPENFHEpke.1.1.2.dylib")
    message(STATUS "Using bundled OpenFHE libraries from ${LOCAL_OPENFHE_LIBDIR}")
    set(OpenFHE_LIBDIR "${LOCAL_OPENFHE_LIBDIR}")
    set(OpenFHE_SHARED_LIBRARIES
        "${LOCAL_OPENFHE_LIBDIR}/libOPENFHEpke.1.1.2.dylib"
        "${LOCAL_OPENFHE_LIBDIR}/libOPENFHEbinfhe.1.1.2.dylib"
        "${LOCAL_OPENFHE_LIBDIR}/libOPENFHEcore.1.1.2.dylib"
    )
    set(OpenFHE_STATIC_LIBRARIES "${OpenFHE_SHARED_LIBRARIES}")
endif()

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )

add_executable( ranking
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/test-ranking.cpp
                                )


add_executable( minimum
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/minimum.cpp
                                        src/test-minimum.cpp
                                )


add_executable( median
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/median.cpp
                                        src/test-median.cpp
                                )


add_executable( sorting
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/sorting.cpp
                                        src/test-sorting.cpp
                                )


add_executable( demo
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/minimum.cpp
                                        src/median.cpp
                                        src/sorting.cpp
                                        src/demo.cpp
                                )

add_executable( eutest1
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/minimum.cpp
                                        src/median.cpp
                                        src/sorting.cpp
                                        src/eutest1.cpp
                                )

add_executable( eutest
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/minimum.cpp
                                        src/median.cpp
                                        src/sorting.cpp
                                        src/eutest.cpp
                                )

add_executable( OkC
                                        src/utils-basics.cpp
                                        src/utils-eval.cpp
                                        src/utils-matrices.cpp
                                        src/utils-ptxt.cpp
                                        src/ranking.cpp
                                        src/minimum.cpp
                                        src/median.cpp
                                        src/sorting.cpp
                                        src/OkC.cpp
                                )
cmake_minimum_required(VERSION 3.10)
project(ProofOfLearning)

find_package(MPI REQUIRED)

option(PVIA_ENABLE_ULFM "Enable ULFM-backed PVIA crash-recovery reference path" OFF)
if(PVIA_ENABLE_ULFM)
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_INCLUDES ${MPI_CXX_INCLUDE_DIRS})
    set(CMAKE_REQUIRED_LIBRARIES MPI::MPI_CXX)
    check_cxx_source_compiles("
        #include <mpi.h>
        #include <mpi-ext.h>
        int main() {
            MPI_Comm c = MPI_COMM_NULL;
            MPI_Group g = MPI_GROUP_NULL;
            int flag = 1, acked = 0;
            MPIX_Comm_get_failed(MPI_COMM_WORLD, &g);
            MPIX_Comm_ack_failed(MPI_COMM_WORLD, 4, &acked);
            MPIX_Comm_revoke(MPI_COMM_WORLD);
            MPIX_Comm_shrink(MPI_COMM_WORLD, &c);
            MPIX_Comm_agree(c, &flag);
            return 0;
        }" PVIA_ULFM_API_AVAILABLE)
    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)
    if(NOT PVIA_ULFM_API_AVAILABLE)
        message(FATAL_ERROR "PVIA_ENABLE_ULFM=ON but required ULFM APIs are unavailable")
    endif()
    add_definitions(-DPVIA_ENABLE_ULFM=1)
endif()

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-w -march=native  -mavx -msha")
set(CMAKE_C_FLAGS "-w -march=native -mavx -msha")



link_directories(lib)
link_directories(Blake)

include_directories(src)
include_directories(lib)
include_directories(Blake)

add_subdirectory(src)
add_subdirectory(Blake)


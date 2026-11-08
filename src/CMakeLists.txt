aux_source_directory(. SRC)
aux_source_directory(accountability ACC_SRC)
include_directories(.)
add_executable(pigeon ${SRC} ${ACC_SRC})

target_link_libraries(pigeon pthread XKCP blake3 MPI::MPI_CXX OpenSSL::Crypto ${CMAKE_DL_LIBS})



# Independent public verifier for source-only native and signed reference
# residual-link receipts. It never accesses a witness or MPC private share.
add_executable(pvia_reference_pair_verify
    ../experiments/pvia_reference_pair_verify.cpp
    accountability/ReferenceResidualPairPublicVerifier.cpp)
target_link_libraries(pvia_reference_pair_verify OpenSSL::Crypto)

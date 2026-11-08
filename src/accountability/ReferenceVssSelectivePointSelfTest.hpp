#pragma once
#include <string>
namespace pvia {
// Fast reference MPI selective point-value recovery selftest.
// Only each missing target receives private point evaluations.
bool run_reference_vss_selective_point_selftest(int rank,int world_size);
bool run_reference_vss_selective_point_process_restart_selftest(int rank,int world_size,const std::string& phase,const std::string& directory);
}

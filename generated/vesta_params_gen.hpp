// GENERATED FILE - vesta_params_gen.hpp
#pragma once
#include <array>
#include <cstdint>
namespace hsma::vesta_gen {
inline constexpr std::array<std::uint64_t, 4> MOD { { 0x992d30ed00000001ULL, 0x224698fc094cf91bULL, 0x0000000000000000ULL, 0x4000000000000000ULL } } ;
inline constexpr std::uint64_t INV = 0x992d30ecffffffffULL;
inline constexpr std::array<std::uint64_t, 4> RR { { 0x8c78ecb30000000fULL, 0xd7d30dbd8b0de0e7ULL, 0x7797a99bc3c95d18ULL, 0x096d41af7b9cb714ULL } } ;
inline constexpr std::array<std::uint64_t, 4> R_ONE { { 0x34786d38fffffffdULL, 0x992c350be41914adULL, 0xffffffffffffffffULL, 0x3fffffffffffffffULL } } ;
static_assert((INV * MOD[0]) == ~0ULL, "n0 identity failed in C++");
static_assert(MOD[0] & 1ULL, "modulus must be odd");
} // namespace hsma::vesta_gen

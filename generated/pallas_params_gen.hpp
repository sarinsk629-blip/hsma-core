// GENERATED FILE - pallas_params_gen.hpp
#pragma once
#include <array>
#include <cstdint>
namespace hsma::pallas_gen {
inline constexpr std::array<std::uint64_t, 4> MOD { { 0x8c46eb2100000001ULL, 0x224698fc0994a8ddULL, 0x0000000000000000ULL, 0x4000000000000000ULL } } ;
inline constexpr std::uint64_t INV = 0x8c46eb20ffffffffULL;
inline constexpr std::array<std::uint64_t, 4> RR { { 0xfc9678ff0000000fULL, 0x67bb433d891a16e3ULL, 0x7fae231004ccf590ULL, 0x096d41af7ccfdaa9ULL } } ;
inline constexpr std::array<std::uint64_t, 4> R_ONE { { 0x5b2b3e9cfffffffdULL, 0x992c350be3420567ULL, 0xffffffffffffffffULL, 0x3fffffffffffffffULL } } ;
static_assert((INV * MOD[0]) == ~0ULL, "n0 identity failed in C++");
static_assert(MOD[0] & 1ULL, "modulus must be odd");
} // namespace hsma::pallas_gen

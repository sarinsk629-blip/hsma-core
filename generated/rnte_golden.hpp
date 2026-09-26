// GENERATED - rnte_golden.hpp
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
struct RnteCase { std::uint64_t mag; bool neg; unsigned s; std::int32_t want; bool want_sat; };
inline constexpr std::array<RnteCase, 32> RNTE_CASES {{
  { 0ULL, false, 16, 0, false },
  { 0ULL, true, 16, 0, false },
  { 1ULL, false, 16, 0, false },
  { 1ULL, true, 16, 0, false },
  { 65535ULL, false, 16, 1, false },
  { 65535ULL, true, 16, -1, false },
  { 32768ULL, false, 16, 0, false },
  { 32768ULL, true, 16, 0, false },
  { 32767ULL, false, 16, 0, false },
  { 32767ULL, true, 16, 0, false },
  { 32769ULL, false, 16, 1, false },
  { 32769ULL, true, 16, -1, false },
  { 32770ULL, false, 16, 1, false },
  { 32770ULL, true, 16, -1, false },
  { 859563060544119437ULL, false, 16, 2147483647, true },
  { 859563060544119437ULL, true, 16, -2147483647, true },
  { 0ULL, false, 32, 0, false },
  { 0ULL, true, 32, 0, false },
  { 1ULL, false, 32, 0, false },
  { 1ULL, true, 32, 0, false },
  { 4294967295ULL, false, 32, 1, false },
  { 4294967295ULL, true, 32, -1, false },
  { 2147483648ULL, false, 32, 0, false },
  { 2147483648ULL, true, 32, 0, false },
  { 2147483647ULL, false, 32, 0, false },
  { 2147483647ULL, true, 32, 0, false },
  { 2147483649ULL, false, 32, 1, false },
  { 2147483649ULL, true, 32, -1, false },
  { 2147483650ULL, false, 32, 1, false },
  { 2147483650ULL, true, 32, -1, false },
  { 2685429951690454587ULL, false, 32, 625250384, false },
  { 2685429951690454587ULL, true, 32, -625250384, false },
}};
}

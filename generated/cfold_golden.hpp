// HSMA :: cfold_golden.hpp - P1-12 golden (DEC-230). CANONICAL limbs.
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
inline constexpr std::array<std::uint64_t, 4> CF_RHO_U { {0x3a9ee36bdd8d34f0ull, 0x1e9482fb1f562821ull, 0x93172f34122c6bf7ull, 0x33df406825833c98ull} };

inline constexpr std::array<std::uint64_t, 4> CF_RHO_1 { {0x1833ba3bdfef7da2ull, 0x30bb60a7d502463cull, 0x5a80142e3088ea31ull, 0x170fe24355535a23ull} };

inline constexpr std::array<std::uint64_t, 4> CF_RHO_T { {0x4cb169435c65f1a9ull, 0x224c56fd2c2509cfull, 0xd39cf242ae88eb86ull, 0x3eb99fd6b37cc6e8ull} };

inline constexpr std::array<std::uint64_t, 4> CF_CW_U_X { {0xc82dba5b8a201c86ull, 0x21f950f1c94d90dcull, 0x43a89bea8f173c44ull, 0x15fb384e818eb0ffull} };

inline constexpr std::array<std::uint64_t, 4> CF_CW_U_Y { {0x517dd8f36f807b3full, 0x86dad30f1e4e42c7ull, 0xb06ae9eedde15ef3ull, 0x101af042d81989faull} };

inline constexpr std::array<std::uint64_t, 4> CF_CW_1_X { {0x9dea7938863ab92aull, 0xa3c7613ec1d18adfull, 0xb63e45d9280d4339ull, 0x085f819ed240a388ull} };

inline constexpr std::array<std::uint64_t, 4> CF_CW_1_Y { {0x6aa964fa270ca957ull, 0x8ce97e98d7d9f455ull, 0xfb968d2fced07176ull, 0x1ae28bd607657da1ull} };

inline constexpr std::array<std::uint64_t, 4> CF_CT_1_X { {0x5e2a5ada632a80a6ull, 0xafad33e85ca4c180ull, 0xf37c4008e964eb52ull, 0x072fa530a847106cull} };

inline constexpr std::array<std::uint64_t, 4> CF_CT_1_Y { {0x6eb905b6891332d3ull, 0x3528d55035922027ull, 0xb5d0078972abde19ull, 0x012e933f7ef5fb4dull} };

inline constexpr std::array<std::uint64_t, 4> CF_R1 { {0xb88ee3ca2fad64e6ull, 0x5f18267a56ad4857ull, 0x721a32d9c4b2ae25ull, 0x00864e0f0cb83e1dull} };

inline constexpr std::array<std::uint64_t, 4> CF_WP_X { {0x4607e3ec62cbc8acull, 0x3356454541135399ull, 0xc6909f6508c33369ull, 0x24b5f35cbbe0a406ull} };

inline constexpr std::array<std::uint64_t, 4> CF_WP_Y { {0xedda75e45adc247eull, 0x2346e98dfc43f1b6ull, 0x4ed74e2a3930627aull, 0x2be922e9e2dfa9a4ull} };

inline constexpr std::array<std::uint64_t, 4> CF_WRE_X { {0x4607e3ec62cbc8acull, 0x3356454541135399ull, 0xc6909f6508c33369ull, 0x24b5f35cbbe0a406ull} };

inline constexpr std::array<std::uint64_t, 4> CF_WRE_Y { {0xedda75e45adc247eull, 0x2346e98dfc43f1b6ull, 0x4ed74e2a3930627aull, 0x2be922e9e2dfa9a4ull} };

} // namespace hsma::golden

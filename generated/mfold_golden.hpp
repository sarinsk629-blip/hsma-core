// HSMA :: mfold_golden.hpp - P1-11 golden (DEC-229). CANONICAL limbs.
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
inline constexpr unsigned MF_ROWS = 4u, MF_COLS = 8u, MF_K = 2u;
inline constexpr std::array<std::uint64_t, 4> MF_SEED1 { {0xed865e39c8c9ce2eull, 0x27550bb8273dedc4ull, 0x4a8360e19796f875ull, 0x2f0bdca3a755eb89ull} };

inline constexpr std::array<std::uint64_t, 4> MF_R1 { {0xb88ee3ca2fad64e6ull, 0x5f18267a56ad4857ull, 0x721a32d9c4b2ae25ull, 0x00864e0f0cb83e1dull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 4> MF_T1 {{
  { {0x8c46eb20fffffff9ull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20ffffffcdull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20fffffffdull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20fffffe71ull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> MF_F1_Z {{
  { {0x711dc7945f5ac9cfull, 0xbe304cf4ad5a90afull, 0xe43465b389655c4aull, 0x010c9c1e19707c3aull} },
  { {0xb88ee3ca2fad64eaull, 0x5f18267a56ad4857ull, 0x721a32d9c4b2ae25ull, 0x00864e0f0cb83e1dull} },
  { {0x29acab5e8f082eb7ull, 0x1d48736f0407d907ull, 0x564e988d4e180a70ull, 0x0192ea2d2628ba58ull} },
  { {0x7d06021bad188c39ull, 0x57d95a4d0c178b15ull, 0x02ebc9a7ea481f50ull, 0x04b8be87727a2f09ull} },
  { {0xe23b8f28beb5939eull, 0x7c6099e95ab5215eull, 0xc868cb6712cab895ull, 0x0219383c32e0f875ull} },
  { {0x88ee3ca2fad64e84ull, 0xf18267a56ad4857bull, 0x21a32d9c4b2ae255ull, 0x0864e0f0cb83e1d7ull} },
  { {0x7655f3edad64eb0eull, 0xd399485e9a1f05fdull, 0x1a32d9c4b2ae255eull, 0x064e0f0cb83e1d72ull} },
  { {0x771206530749a4f1ull, 0x078c0ee72446a140ull, 0x08c35cf7bed85df1ull, 0x0e2a3b96576e8d1bull} },
}};

inline constexpr std::array<std::uint64_t, 4> MF_F1_U { {0xb88ee3ca2fad64e7ull, 0x5f18267a56ad4857ull, 0x721a32d9c4b2ae25ull, 0x00864e0f0cb83e1dull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 4> MF_F1_E {{
  { {0xc7cfcccf8294d8d1ull, 0x29856529542a661full, 0x6f2e6931da6a8ed5ull, 0x3bcd8f879a3e0f14ull} },
  { {0x0f40a60f50c78149ull, 0xd15ec8226e61f70cull, 0xd2adabc40bb4a068ull, 0x24b824f16a936204ull} },
  { {0xaa0b5bf8414a6c69ull, 0xa5e5ff12aedf877eull, 0x37973498ed35476aull, 0x3de6c7c3cd1f078aull} },
  { {0xd1d7c099811258a4ull, 0xf35e44c8b7919a65ull, 0xb7108bbca8cfe59bull, 0x2e26087c201ef1fdull} },
}};

inline constexpr std::array<std::uint64_t, 4> MF_SEED2 { {0x4c812f3e0bf586fcull, 0xa443a895b882548full, 0x071d3c807ff23968ull, 0x01ddb6874d21a24dull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 1> MF_R2 {{
  { {0xe5a1538788167f94ull, 0x269d2afd885bb721ull, 0xba66bdeaa519b26cull, 0x2a8fcb7dc566f578ull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 4> MF_T2 {{
  { {0x8c46eb20fffffff9ull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20ffffffcdull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20fffffffdull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
  { {0x8c46eb20fffffe71ull, 0x224698fc0994a8ddull, 0x0000000000000000ull, 0x4000000000000000ull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> MF_F2_Z {{
  { {0xb01983826f87c8f6ull, 0xe92409f3b47d5615ull, 0x5901e188d398c122ull, 0x162c3319a43e672cull} },
  { {0x9e303751b7c3e47eull, 0x85b55177df08ff79ull, 0x2c80f0c469cc6091ull, 0x2b16198cd21f3396ull} },
  { {0xc202cfb3274bad71ull, 0x4c92c26f89f1acb1ull, 0x8582d24d3d6521b4ull, 0x01424ca6765d9ac2ull} },
  { {0x46086f1975e30867ull, 0xe5b8474e9dd50615ull, 0x908876e7b82f651cull, 0x03c6e5f36318d047ull} },
  { {0x60330704df0f91ecull, 0xd24813e768faac2bull, 0xb203c311a7318245ull, 0x2c586633487cce58ull} },
  { {0x683e45d17c3e47baull, 0x04931da590c15ef2ull, 0xc80f0c469cc60917ull, 0x316198cd21f33962ull} },
  { {0xf091578bc3e47e64ull, 0xade2ae88991e04c3ull, 0x80f0c469cc60916eull, 0x16198cd21f33962cull} },
  { {0xd2194d4c61a9197bull, 0xb128d5ebd97f123full, 0xb19964b7288e2f56ull, 0x0b54b1da294a70d6ull} },
}};

inline constexpr std::array<std::uint64_t, 4> MF_F2_U { {0x9e303751b7c3e47bull, 0x85b55177df08ff79ull, 0x2c80f0c469cc6091ull, 0x2b16198cd21f3396ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 4> MF_F2_E {{
  { {0x5827c83841e0dc36ull, 0x9ffd0a294133f964ull, 0x9bf879dcb19cfb74ull, 0x274f33996f06634eull} },
  { {0x982dd40aac35975cull, 0xa918f7180b13da73ull, 0xf5cf181a827c6275ull, 0x3f82cf6551a9857eull} },
  { {0x2c13e41c20f06e1bull, 0x4ffe8514a099fcb2ull, 0x4dfc3cee58ce7dbaull, 0x13a799ccb78331a7ull} },
  { {0xc7758d1eddeb026eull, 0x3b260e859cbaeba2ull, 0x7687cd1ab0a91cc3ull, 0x2d7813f7af3f655aull} },
}};

} // namespace hsma::golden

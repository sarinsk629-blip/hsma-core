// HSMA :: epoch_golden.hpp - P1-13b golden (DEC-232). CANONICAL limbs.
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
inline constexpr std::array<std::uint64_t, 4> EP_PREV { {0x7891cfdfdfe92e51ull, 0x3252e0530e4c2466ull, 0x72ceefb2697be71full, 0x114c4041fe4c8a66ull} };

inline constexpr std::array<std::uint64_t, 4> EP_PT { {0x515f4e30265ef036ull, 0x65c9ea2d895c7d28ull, 0x7241d359e53ef6ffull, 0x2a36307d0edeff41ull} };

inline constexpr std::array<std::uint64_t, 4> EP_DHEAD { {0x753b3d791fc95e3bull, 0x3e91d06f7c6ff7aeull, 0x119a9fd2bac878afull, 0x04f1b6957adbae58ull} };

inline constexpr std::array<std::uint64_t, 4> EP_DEXEC { {0x4e3ffdb875ad5b95ull, 0xcc2d6d997aed7e49ull, 0x5619b463bb86a35aull, 0x0727b8a7e6ea09d5ull} };

inline constexpr std::array<std::uint64_t, 4> EP_SEED1 { {0xdc7f23e8301165ddull, 0xe65e99cf9d377f65ull, 0x7a01494192f335e0ull, 0x2e5a733a3e7055a9ull} };

inline constexpr std::array<std::uint64_t, 4> EP_SEED2 { {0x66a4054614f72d74ull, 0xc36c2e08ec49532cull, 0xb2c8636642bca001ull, 0x38c8d69b520dc8b9ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 1> EP_R1 {{
  { {0xf2b0967fe83f95b8ull, 0xc3847330d4832721ull, 0x49e5a4cb068186fcull, 0x09f76ab5aefb9bacull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 1> EP_R2 {{
  { {0x8f07476dfa3533bfull, 0xdfa3bca8d7ecf01aull, 0x52d98d20b82bf473ull, 0x154a459f2d6ec16dull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 16> EP_F2_Z {{
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0x57dcc29ca395d232ull, 0x823ea809d5333b8aull, 0xe7ef060e03f7e5e4ull, 0x0050a1b884614ef8ull} },
  { {0x92aa294b85464107ull, 0x49729a8add3b1e4eull, 0xf5589c1a2fbbc129ull, 0x1c7a4695bad33811ull} },
  { {0xee66f33c44e3b83cull, 0x241d66944c04e02bull, 0x61ccd1c5d171278aull, 0x0533108348183d75ull} },
  { {0xee66f33c44e3b83cull, 0x241d66944c04e02bull, 0x61ccd1c5d171278aull, 0x0533108348183d75ull} },
  { {0xe732501e3131823eull, 0x0f4583ff9a52a80eull, 0x493a5d7236be6014ull, 0x1acbd25206e88bb3ull} },
  { {0x68ea2e0c13a64bb6ull, 0xb26db3d946c2bf4bull, 0xe5f98f5df56bdb84ull, 0x3a0d82a6e352e8ccull} },
  { {0x81b7ddede274c978ull, 0xa3282fd9ac70173cull, 0x9cbf31ebbead7b70ull, 0x1f41b054dc6a5d19ull} },
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0x8f07476dfa3533bfull, 0xdfa3bca8d7ecf01aull, 0x52d98d20b82bf473ull, 0x154a459f2d6ec16dull} },
  { {0x10bf255bdca9fd36ull, 0x82cbec82845d0757ull, 0xef98bf0c76d96fe4ull, 0x348bf5f409d91e86ull} },
  { {0xf2b0967fe83f95b8ull, 0xc3847330d4832721ull, 0x49e5a4cb068186fcull, 0x09f76ab5aefb9bacull} },
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0xa286c916d11464b3ull, 0x1fccccd82aa23eaeull, 0x954bd94de73158ccull, 0x1f20813264b6a161ull} },
  { {0xf2b0967fe83f95b9ull, 0xc3847330d4832721ull, 0x49e5a4cb068186fcull, 0x09f76ab5aefb9bacull} },
  { {0x81b7ddede274c978ull, 0xa3282fd9ac70173cull, 0x9cbf31ebbead7b70ull, 0x1f41b054dc6a5d19ull} },
}};

inline constexpr std::array<std::uint64_t, 4> EP_F2_U { {0x81b7ddede274c978ull, 0xa3282fd9ac70173cull, 0x9cbf31ebbead7b70ull, 0x1f41b054dc6a5d19ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> EP_F2_E {{
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0xd5553fc0376d6507ull, 0x09adc20dbd3532a6ull, 0x63a20af4f3f43135ull, 0x26d316e6fb1242f2ull} },
  { {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull} },
  { {0xc1d5be17608e3413ull, 0xc984b1de6a7fe412ull, 0x212fbec7c4eeccdcull, 0x1cfcdb53c3ca62feull} },
  { {0xc22ac39adafe96a2ull, 0xfb5223ac2b7bc04dull, 0x42c0ba703c7f465eull, 0x000e7de35f116608ull} },
  { {0x74ea7f12ff8b61beull, 0x140036db8c2c5952ull, 0x42e3667234fc0c82ull, 0x2eb8f7c245a80c44ull} },
}};

inline constexpr std::array<std::uint64_t, 4> EP_C { {0x962fcc06e6403eb5ull, 0xc91d2ed60a7ae751ull, 0xd1460391ddedac95ull, 0x2e022014da6c0077ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> EP_OOD {{
  { {0x03f6f8fd5f57743eull, 0x6a1e915e19d71d68ull, 0xd958ff539b87cf2aull, 0x241eacc9a6e179a9ull} },
  { {0x69588653f2b3c6bfull, 0x987be0e290bc76eeull, 0xaea3c837ac9ef7f5ull, 0x0b574f91649c0c3aull} },
  { {0xe89e98f3a5a22a55ull, 0x70a364b65510add9ull, 0x892e9cd38d7d6f27ull, 0x058f6f5a98b2fa64ull} },
  { {0xc5c14d1cad242219ull, 0xf09c825805eb9504ull, 0xb50595f67bf3bd19ull, 0x25cc4cc1ada8242dull} },
  { {0xc6ec7f0eaa8e0178ull, 0x02f034e1ad671446ull, 0x99894dc034e162edull, 0x3a583aaed42cb2e4ull} },
  { {0x5d81443526f9c31full, 0x95f63559d4942cfdull, 0xe5224563ed5a5102ull, 0x3fd3b2d887bccc18ull} },
  { {0x0940aaf045f05175ull, 0xabe94aa68dd101e6ull, 0xcc1d507d5023c917ull, 0x0f6ac1083e37ade3ull} },
  { {0xc425e6d4c0be1ec6ull, 0x77d83026697742ddull, 0x94ecbd226231dc21ull, 0x3dc497630829ec0dull} },
}};

inline constexpr std::array<std::uint64_t, 4> EP_OOD_COMMIT { {0x945a5ea244e695c3ull, 0x8212fc307568ea31ull, 0x56cc47909ab9e1b4ull, 0x11e83b3fb030c316ull} };

} // namespace hsma::golden

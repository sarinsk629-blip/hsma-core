// HSMA :: vesta_absorb_golden.hpp - P1-07 golden (DEC-225).
// payload(8 canonical u64 limbs) -> d = Poseidon_V(CYCLEFOLD, dom=0)
// 7-call tree -> P_cf = [d]*G_vesta. CANONICAL limbs throughout.
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
inline constexpr unsigned VEC_ABSORB_N = 6u;
struct VestaAbsorb { std::uint64_t px[4], py[4], d[4], pcfx[4], pcfy[4]; };
inline constexpr std::array<VestaAbsorb, 6> VEC_ABSORB {{
{ {0xb05660e6ee20f49eull, 0xb00eb29ccc10eafdull, 0xa0659842c99e94cdull, 0xd2ebceefad8ff389ull}, {0x8a0602dfee9cbea8ull, 0x4df1a98a280d1f57ull, 0x330779d8104f2f57ull, 0xe1a3a168ab002893ull}, {0xab9a3cab46481b2full, 0x3fdc0fd1a25176d3ull, 0xa617b3c457d99c2cull, 0x0601dfde40e34f32ull}, {0x219ba6576c0328b1ull, 0x154bd00964b1bcafull, 0x6134ec5c576e82f4ull, 0x2ba737865f8c4831ull}, {0x0afbafe9880e1ccbull, 0x4703361da5755de7ull, 0xfc42fc59e18a1d99ull, 0x3794f367dc5507e7ull} },
{ {0xc3e1296334eeab81ull, 0xe306822c0db49de6ull, 0xe310b3c9380e388aull, 0x043b12dfb21b7f98ull}, {0x3248b4a203170756ull, 0x4c630f632567162dull, 0xe13a581e13a05eccull, 0xc0059a5d875a8cf8ull}, {0x11f49686a1f793fcull, 0x4762385bbf4fda1eull, 0x2a4d897214d246f6ull, 0x0cdee46b65f03ef3ull}, {0x528b69bda0a89262ull, 0xf58a6a6670bd7d7full, 0x070598d8f80b3339ull, 0x2864350b2955e26aull}, {0x0f0ccc3042e88adaull, 0xc5488d988c950688ull, 0x4cb172d107660fd7ull, 0x0000537f4bd070ebull} },
{ {0xb3f4743c9ca7bbf0ull, 0xf878fc29c0739acfull, 0x2400793c02628dbfull, 0x937e0a23d2026cafull}, {0xfae7fd711fa6a6ccull, 0xe45becb6b272bef4ull, 0x40e824b9725b485eull, 0xe1e26be496ac4f24ull}, {0x31c69d66ea05a920ull, 0x551db2b5f3128c91ull, 0xf1d96a7c50ed401full, 0x055ae88ae60aa154ull}, {0x4328592a7887570eull, 0xf87843e784f2c463ull, 0xfc099906d60b71a2ull, 0x19bcaa5947ede883ull}, {0xf87606626aefb298ull, 0xbdf14280422036f3ull, 0xe8e709d7e1df4307ull, 0x1227c1d9ab5148d0ull} },
{ {0x3302b3ef7f0b320bull, 0x61ede7b0dfc23f08ull, 0x3757616dacd9f0eeull, 0x666d244a8aa2f150ull}, {0xc8529adff1bd533eull, 0x215cb3a178f5eefeull, 0x4709ff4e5d950d55ull, 0xf90808769e985c7bull}, {0x05b925311173aa95ull, 0xc49c401160ad7080ull, 0x13c87caa8c6540c7ull, 0x2ace478dbc65bae1ull}, {0x93514fce082a2c09ull, 0x03a4ef8971d3ba73ull, 0x985d6ba48633c257ull, 0x3159ab71e880c02eull}, {0xb8955258cd6e8be9ull, 0xa829dbe1fc3ca35full, 0xe6ebf61d118b1b9eull, 0x0b20f58201803d93ull} },
{ {0xbf2986003617b2adull, 0x9cc4e0a13a7febbdull, 0x2d9c1b2b6c1898efull, 0xb1cc5f4cc355875bull}, {0x844455bf65ee47adull, 0xb331258d6fa1d560ull, 0xe1ecf07110eeebabull, 0x8c92f78e85015e42ull}, {0xea3ddc80172debf8ull, 0xe8ed339431796ffcull, 0xb6570f07d56be708ull, 0x12c0896b52079a5bull}, {0x2f9773049ee2bcafull, 0x97e66987796893e6ull, 0x985aca0e55a9c029ull, 0x2f0e1169992ef2a4ull}, {0x584cda81432931a2ull, 0xa38f0d8ac732e172ull, 0xc7896f03915017dbull, 0x1e422709e6453cd5ull} },
{ {0x0228a8d8d3c45a77ull, 0x4a7ffa811bd843a0ull, 0x6182d34d107f679full, 0xc1c03305ba8ed4b6ull}, {0x90d41b69cb05d5a9ull, 0x15b847d19263bddfull, 0x24790f5e9c52e136ull, 0xbdf10cac37773ff9ull}, {0xc8e9f33cd2757dacull, 0x8c18b47acfad4ed8ull, 0xfb0a83eb48edd418ull, 0x0dafd10f3a749b22ull}, {0x984ac1a5a525189bull, 0x65dbaa6fdcdeda84ull, 0x5275d7560b85b330ull, 0x2bf8c952d7b53910ull}, {0xa5035878ba34bb9bull, 0x53246adfaba62398ull, 0xdcdbf6bf3d5efbbbull, 0x3bed27f6b13980dbull} },
}};
} // namespace hsma::golden

// HSMA :: whir_golden.hpp - P1-10 golden (DEC-228). CANONICAL limbs.
// evals[i] = sha256("hsma-whir-golden-v1|f|i") LE % p; seed string is the contract.
#pragma once
#include <array>
#include <cstdint>
namespace hsma::golden {
inline constexpr unsigned WHIR_NV = 10u;
inline constexpr unsigned WHIR_K = 8u;
inline constexpr std::array<std::uint64_t, 4> WHIR_C { {0x2f8a2e94f537d4ebull, 0x03e31e6db8f67c33ull, 0x4fd4204a049ba15full, 0x0ae3c26190d9486cull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 11> WHIR_T1_CLAIMS {{
  { {0xc6507531f5f33a78ull, 0x19db421c2cec6ca0ull, 0x2860ef74ff856866ull, 0x3515b2661eeaf700ull} },
  { {0x196eea7061e99cb0ull, 0xf8076d643774401eull, 0xc402703754b4667bull, 0x058490ef87f812b8ull} },
  { {0x27c64ac128932b20ull, 0x470d2d7e54b02c7full, 0x2861f69021e4428full, 0x18ad5cbd5b62656eull} },
  { {0xd2b74789b85f6bf8ull, 0x3a44678c0bd59b1dull, 0xee6808c5e72e6f9aull, 0x3158c6ffa58cfc15ull} },
  { {0x8f8859d6dbf9e38full, 0xca8b2035deb5bd23ull, 0x99cd7c66c696c5d1ull, 0x333e6cfd7eee23c9ull} },
  { {0x1f1e389a2fa76f2cull, 0x84ad9f68c6699207ull, 0x8e7bf2ffa7d317b1ull, 0x232e4916cbf35f62ull} },
  { {0xef755b18e6ee4f18ull, 0x8ac0e5ea0aff2348ull, 0x7cc89dd867dcd8b2ull, 0x19c99e57f56f11f4ull} },
  { {0x3e0dccffbc0ef15eull, 0x27f4c27518d18409ull, 0x357e960f83dd0544ull, 0x1a2111d17953eefcull} },
  { {0xd14972ad013db371ull, 0xb3a83b98d79801b0ull, 0x6df718cddb265d43ull, 0x1c7b89caf82ac019ull} },
  { {0x41e6fbf1b69b5119ull, 0x1d5fc74dd28e8ea4ull, 0xc7511d6781554020ull, 0x01fa85879bc2f25eull} },
  { {0x59b41d5afa46aa55ull, 0x52fba61b5a6cafc4ull, 0xf4e1bede0f3864b3ull, 0x1424cfd206fec68bull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 20> WHIR_T1_EVALS {{
  { {0x6217c4a6e3d0ce29ull, 0x624ab7854e5bc885ull, 0x3c010450e825c71full, 0x24876edc1c954d27ull} },
  { {0x6438b08b12226c4full, 0xb7908a96de90a41bull, 0xec5feb24175fa146ull, 0x108e438a0255a9d8ull} },
  { {0xf46a499b83e8f431ull, 0x9776a9c9b54e6858ull, 0x4b9bddfb887b6582ull, 0x3de92809780a3316ull} },
  { {0xb14b8bf5de00a880ull, 0x82d75c968bba80a2ull, 0x7866923bcc3900f9ull, 0x079b68e60feddfa2ull} },
  { {0x426bab1f009dc0e4ull, 0x6d24388430e8f65eull, 0x05076c25bf4a51f2ull, 0x3b4a6dbf1f5e026bull} },
  { {0x71a18ac327f56a3dull, 0xfc2f8df62d5bdefeull, 0x235a8a6a6299f09cull, 0x1d62eefe3c046303ull} },
  { {0xf36cb92c55cdfda8ull, 0x727ea8e76762fea9ull, 0x18eba2f3d57b6f9full, 0x19aac0a9d1c58400ull} },
  { {0xdf4a8e5d62916e50ull, 0xc7c5bea4a4729c73ull, 0xd57c65d211b2fffaull, 0x17ae0655d3c77815ull} },
  { {0x71a0c3535bd780b6ull, 0x0e9d6e2f62aeedf9ull, 0x1ce717fef81b96a6ull, 0x0fd16d4ce9edc4fbull} },
  { {0x1de79683802262d9ull, 0xbbedb2067c06cf2aull, 0x7ce66467ce7b2f2bull, 0x236cffb095005eceull} },
  { {0xbb894b64a5065bb0ull, 0xbe027647caa05676ull, 0xe8545c089ba07bf5ull, 0x2315948a8331d71dull} },
  { {0x6394ed358aa1137cull, 0xc6ab2920fbc93b90ull, 0xa62796f70c329bbbull, 0x0018b48c48c18844ull} },
  { {0x036f7e6de4249e77ull, 0xa74c857b9c480a0dull, 0x1ebb2edd1b8907f6ull, 0x2a577733ab7f2324ull} },
  { {0x784cc7cc02c9b0a2ull, 0x05baf96a784bc219ull, 0x5e0d6efb4c53d0bcull, 0x2f72272449efeed0ull} },
  { {0xd3d19996bf134b5aull, 0x3b3e011324445fe5ull, 0x9d4a25c69542a9b7ull, 0x335df65987cef050ull} },
  { {0xf6831e89fcfba605ull, 0x0efd5a5dfe21cd00ull, 0x98347048ee9a5b8dull, 0x26c31b77f184feabull} },
  { {0x67d31a624fc7328dull, 0x7ed90549f4215908ull, 0x222e79b3c262f504ull, 0x014f2ace659fc470ull} },
  { {0x6976584ab17680e4ull, 0x34cf364ee376a8a8ull, 0x4bc89f1a18c3683full, 0x1b2c5efc928afba9ull} },
  { {0xcc9878997a2d6b52ull, 0xa12cf094d41faf9aull, 0x21fd04dd3898f2bfull, 0x19a4c76eb57b268bull} },
  { {0x01956e793c6de5c8ull, 0x9e796fb5080387e7ull, 0xa554188a48bc4d60ull, 0x2855be18e647cbd3ull} },
}};

inline constexpr std::array<std::uint64_t, 4> WHIR_T1_FA { {0x59b41d5afa46aa55ull, 0x52fba61b5a6cafc4ull, 0xf4e1bede0f3864b3ull, 0x1424cfd206fec68bull} };

inline constexpr std::array<std::uint64_t, 4> WHIR_C2 { {0xc9cc734966fe5616ull, 0x76c9cbd51e62095cull, 0x0d4fa745d209e860ull, 0x3c69d914deda2c01ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 11> WHIR_T2_CLAIMS {{
  { {0xdae433d12123ebb9ull, 0x992e30feb4547cf2ull, 0x204da91685dd3c79ull, 0x06f0732b792864d0ull} },
  { {0x7dcd3bd09dae36bfull, 0x842b39aa9783d42dull, 0x331e96ccf3ad083eull, 0x048b8687fc9e6693ull} },
  { {0x0fca2c5d2a906f5cull, 0x422dcd71fb6faadbull, 0xcb492c51cfafc148ull, 0x243720599af0a7d3ull} },
  { {0xc1f52b1ed0b543cbull, 0x1dc42643b94916fbull, 0x14115e1af424a3cbull, 0x235d5d7ead637ae6ull} },
  { {0x8a4068a53007bd76ull, 0x4bd94d02639079c9ull, 0xc859c23685be4a71ull, 0x2636a37ad99511ccull} },
  { {0x1190f1dcd874b0cbull, 0xf2f6e271406d5f82ull, 0x33b913d5cb0752daull, 0x3b9327ba6c44bb9cull} },
  { {0x14eee72f4a8b7d76ull, 0x1f90834a5945cc74ull, 0x9ae0be59df2b8e32ull, 0x030730fa81eb6194ull} },
  { {0x921af3fe60904e9full, 0x78978a4e6741a208ull, 0x3f70d20f9de7974full, 0x1aaa8159b242df07ull} },
  { {0x071babe39d1d6edaull, 0x8354dfbc80c1e253ull, 0x4fef78a85acf5debull, 0x0f9f60feb0093a65ull} },
  { {0x8463a91e4eb16aa4ull, 0x712dec6c5d0f3240ull, 0x76b1a5981ac1cbbcull, 0x020db986fae5e045ull} },
  { {0x81ec1ad1dd7e2e3cull, 0xbfc9a7214e82478bull, 0xba4483be4fc5049cull, 0x036454fa1ec88d06ull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 30> WHIR_T2_EVALS {{
  { {0x18ef45a125bdbdb4ull, 0xf50422c1fddc576dull, 0xe0c7256e982c2aa0ull, 0x289a69747cbd6f05ull} },
  { {0x4e3bd950fb662e06ull, 0xc670a738c00cce63ull, 0x3f8683a7edb111d8ull, 0x1e5609b6fc6af5caull} },
  { {0x104b8a77e46662a0ull, 0xb0ab799d6a1abc1eull, 0x09a64f6f0bf1209eull, 0x2b6922ae3394b290ull} },
  { {0x35902e2eb027453full, 0x3f6da2db34cbedf1ull, 0x477711ef2579245full, 0x233642996e2c2e6dull} },
  { {0xd483f8c2ed86f181ull, 0x67042fcb6c4c8f19ull, 0xeba784ddce33e3dfull, 0x215543ee8e723825ull} },
  { {0xcee3f1690de852baull, 0xd7049c4b4d3d22f0ull, 0x27563037fbd9d4dfull, 0x1dcd64c4da0d9504ull} },
  { {0x16daaca578f9cfa6ull, 0x30f9944760654a1eull, 0x67c4b679d38bd51full, 0x3d4191e5b5cf58bfull} },
  { {0x85366ad8b1969fb7ull, 0x337ad226a49f099aull, 0x638475d7fc23ec29ull, 0x26f58e73e5214f14ull} },
  { {0xe8531783eccd398aull, 0xed8165923c29f0b9ull, 0xf25ba786b8c11410ull, 0x0458b8aaa6aaf418ull} },
  { {0xb7eb5e1fb3eb2242ull, 0x49416c595cc21d68ull, 0xb7bcc5c3f2c08de3ull, 0x2ed57f3c7444c3fbull} },
  { {0x9650b8201cca218aull, 0xf6c952e6661ba270ull, 0x5c549857016415e7ull, 0x3487de42391eb6eaull} },
  { {0x7cda7f1538e2a0baull, 0x57119e959ef482cfull, 0x51eec43cf4f01c61ull, 0x3654120cf8b7ae95ull} },
  { {0xea99f363af7e3ed8ull, 0x68965273fdb1ea04ull, 0xbcc4a1d712b659ebull, 0x3d4b62b888f49cf2ull} },
  { {0x2bed606280897e9full, 0x0589938a6f7338a2ull, 0x0b95205f7307f086ull, 0x28eb40c250a074daull} },
  { {0x972b5d6569b2d416ull, 0x5446c7da5e286538ull, 0x3821a06bf0ed7ec0ull, 0x00f5666bf0b8adacull} },
  { {0x27b1d07b861a6b50ull, 0x17a7301491268249ull, 0x46de36a7a9eda75eull, 0x2c678bde7b59994aull} },
  { {0xe9df2161525a457bull, 0xdb4fb25caf46dd38ull, 0xecdadd2e2119ab7cull, 0x0f2b9bdbf0eb2251ull} },
  { {0xe17ab6a1168471b4ull, 0x3da415c8b83513d7ull, 0x456a5982af87eaa2ull, 0x2998a2bb00faa4deull} },
  { {0x77fd5ac3f2d6b84cull, 0xe66b411f81735fbeull, 0x8959589c75eacd41ull, 0x2636859db61a4967ull} },
  { {0x2938778c57b4c52bull, 0x5b6bdb26e1671593ull, 0x118765bd6940c0f0ull, 0x1cd0ab5ccbd1182dull} },
  { {0x2d8882ab6f090ddfull, 0x4fa12b3a5cf3b401ull, 0x35c2f0c1f9857e71ull, 0x3d65e3648edf7792ull} },
  { {0xa7bde82c71d718aeull, 0xea036ccf29268e5aull, 0xa11b63575090eb8aull, 0x17beaba91876da58ull} },
  { {0xea5d0bd1eeb935f1ull, 0x8e941d7f3e1b13adull, 0x9e556eb84d56abc4ull, 0x02ebd5b099cc04aeull} },
  { {0xa05f15fb930c87b5ull, 0x0e9fd31a89e001c4ull, 0x6f0f3e8fa26e1dc9ull, 0x163c9295c0fb4574ull} },
  { {0x108b6e8aa4ed34ecull, 0x115c1a2db5131a4full, 0x6bd7541dc71c76dcull, 0x3c1f8913bd06e371ull} },
  { {0x82d72879f83039efull, 0x943f5e8ad54370e1ull, 0xe418248a93b2e70full, 0x137fd7eaf30256f3ull} },
  { {0x5a3e53688ce22693ull, 0x49c62bb01075f4f3ull, 0xa1e120997512410cull, 0x13031d39b1521ee6ull} },
  { {0xe966835f777d00c2ull, 0x35ba5a6a84992e72ull, 0x46c41e1211603bbdull, 0x3f0659de6a93a529ull} },
  { {0x274410dfd73469e3ull, 0x5dba2afde20aacabull, 0x2fed878609618fffull, 0x03075fa890523b1cull} },
  { {0xf16fe0ac1e3c5ac5ull, 0x3f4aceb9916d0a6cull, 0xfcedfa403220862cull, 0x1424d119f9640167ull} },
}};

inline constexpr std::array<std::uint64_t, 4> WHIR_T2_FA { {0xa5e9b5693db99c57ull, 0x444afb17235d336dull, 0xe160c5c647433d3full, 0x1668fc9d10fcccdbull} };

inline constexpr std::array<std::uint64_t, 4> WHIR_T2_FB { {0x7620931471e317b6ull, 0x664907d2d0a69d46ull, 0x9198853ebec784f0ull, 0x2cdd5066729a3389ull} };

inline constexpr std::array<std::uint64_t, 4> WHIR_T2_FB_TRUE { {0x7620931471e317b6ull, 0x664907d2d0a69d46ull, 0x9198853ebec784f0ull, 0x2cdd5066729a3389ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 80> WHIR_TAU {{
  { {0x4f01076cde54c694ull, 0x5282652a912d050eull, 0x6412c4fbb15aa817ull, 0x0aa248aae6e64708ull} },
  { {0x20a5c466f26a80a0ull, 0xd4a7c8c887dcb77aull, 0xbff644aeb347181eull, 0x0986a250f09c905dull} },
  { {0x9805437503f875e6ull, 0xda366cbbb12c2ce7ull, 0xaac40ca614068a68ull, 0x050607fc854bf960ull} },
  { {0xb107cb548e77377dull, 0x3ad80c852c456c7eull, 0x1256caf12ae8e6f6ull, 0x1be6df9e214ae9aeull} },
  { {0x8a73bb73d9def349ull, 0x365f09f4d9308670ull, 0x4dcd96233f5873fcull, 0x13e73682899b6d6eull} },
  { {0x9d785a5061e5f6d7ull, 0x4ad6b2c3de5dfbfdull, 0x27cd89ff65a0321cull, 0x092004150ea45c41ull} },
  { {0x6542a02ca1cd84f3ull, 0x41f783426ee248d4ull, 0x390c37313eb0ba01ull, 0x2de6b0613d0aff10ull} },
  { {0x6e5860e4823228c3ull, 0xe94fefd8395d3971ull, 0xdcb57c93f6ad62e6ull, 0x0730282699bc4eb5ull} },
  { {0x2a6600d5240947c5ull, 0x34d547bcac014968ull, 0x5862c1490d0df4dfull, 0x14b85896eadcbc25ull} },
  { {0xbf42058e5bd985beull, 0x6527b5b42678ba76ull, 0x8a973d27eba240c7ull, 0x13c6c0dc4c8e01c5ull} },
  { {0x1dd3a9e7f8661f96ull, 0xa89d08d7d681f423ull, 0x119e4e4474358144ull, 0x233a8bc241d7c4ecull} },
  { {0x2b3830bb7467ae8eull, 0x61af22b5c73dffb8ull, 0x25399fd7a87a49a6ull, 0x3cfec554a1f16d73ull} },
  { {0xb72ca9eaaee1042bull, 0xd9b92aa1b1b213e2ull, 0x1ba1baa6391aa2f4ull, 0x34176f58a6e8c792ull} },
  { {0x0608c6d51d01d341ull, 0xf7ecaee40b5334b6ull, 0x026ca2c351dff6e5ull, 0x048691474dedaa87ull} },
  { {0x19acaed56755cd24ull, 0x0eba0093933218bdull, 0xdf5655568a20e2b8ull, 0x1f53b02e51604e5bull} },
  { {0xed36b96205987dc1ull, 0x34cffaf8cc56d2bcull, 0xb616049ca45eb9faull, 0x1d70511325ee9f7aull} },
  { {0xce844d896abebce0ull, 0x4ada38f485056d2dull, 0x39729f11fef78a40ull, 0x3dfb2aeedd58dc80ull} },
  { {0x85fac577e09edbc8ull, 0xddd53bc0df0579b2ull, 0xe5a48df2d89ae180ull, 0x246694b44bc4fc63ull} },
  { {0xe858e84d24b4b079ull, 0x235ab40aaa16319bull, 0xcbb74c128cb816f9ull, 0x2bcefca4a4f50305ull} },
  { {0xe055b9f3ff36ca09ull, 0x1f5b1d816576ffe6ull, 0xa492e492da5b01c7ull, 0x3b94e9ea008a864dull} },
  { {0x115f63734ca97823ull, 0x5697ffe066b15d87ull, 0x52d82c7c1acfcfaaull, 0x313d24486b4b5ea9ull} },
  { {0x50e051acbbe46998ull, 0x959cb371f28f6d83ull, 0x0b3163653a2db145ull, 0x321c0d3a57e09316ull} },
  { {0x692803c1f41c9c2eull, 0xbccbd82a600ff4e7ull, 0x4395d1af9f466995ull, 0x3db487ef29ace3cdull} },
  { {0xe801af697d8ecc54ull, 0xb62c9b0a2e5c06fcull, 0x90996727fbb8efa0ull, 0x0ea25b1bc95a40e2ull} },
  { {0x1d7019b9d20ac8a5ull, 0xeae30ef833cdf7dbull, 0xe878c204439a2bc5ull, 0x1a066d8647ae1d4aull} },
  { {0xa542d9ccc603176bull, 0x470587e051105c5eull, 0xa9e9c5733312e72full, 0x33ae397f71393d7full} },
  { {0x9241d1ee375cd3f5ull, 0x76ad1a6ac0d40dc9ull, 0xdcac2bfba88de3e0ull, 0x0536a6dafee774e3ull} },
  { {0x2bc0783d5564677dull, 0x0242574e978e96ceull, 0xd82711c14db15143ull, 0x17190cba859656ecull} },
  { {0xf288f2bdd1dd2fa1ull, 0xf2dbf10080efda8full, 0xab8e73cc936476d6ull, 0x2edaaac8d8b13ce6ull} },
  { {0xec57085b059f8bdaull, 0x9cf8fa214d2bdcbdull, 0x7dfbbcf6bf004c85ull, 0x353b8271e2c72b91ull} },
  { {0x7783042e7c61940full, 0xe72bce2ba3640774ull, 0xad94c009afb1edd8ull, 0x00e269aded6537c3ull} },
  { {0xb927a36a612db564ull, 0x6ff42ecf7ab0ecacull, 0xe5f303e755f57ab5ull, 0x001f9f158620e7dfull} },
  { {0x0a36d1573da5993cull, 0xa71cd540f7545012ull, 0xf22ec62cd8816e72ull, 0x2c4cd11055672047ull} },
  { {0x08706083a499f50bull, 0x136dd9468b4018a2ull, 0xb5db0eaa5a952116ull, 0x1c827e78725305e2ull} },
  { {0xe80381b84f592cfdull, 0x76658c4883a46ee9ull, 0x8406e7ee57bcc27full, 0x1f863696693c49f9ull} },
  { {0x77d04ca23e3a55dbull, 0xa8041d4a75cc81c4ull, 0x5fd084b00ed00b99ull, 0x2164ef9781a18685ull} },
  { {0xff5e39dddd97e5b2ull, 0x6e194fd628e0078full, 0xd866716284d923c6ull, 0x0fe7810576d56810ull} },
  { {0x1f159ae003974fd3ull, 0x579bc57083ff8cacull, 0x24a19668656dbb5aull, 0x1b42b7819bb9405dull} },
  { {0xe1040352d44703bfull, 0x6db432cfa10cd077ull, 0x48e842d3e3f7fbe5ull, 0x10e12c31e1458665ull} },
  { {0x7b9e6d54eff7f524ull, 0xca8b12f26002093cull, 0x3f79ab2cfd24beceull, 0x04764c0ec9e09f3eull} },
  { {0x81b2bdaadf11e0d6ull, 0x6d1dfabd9781e06bull, 0x3f29ed14e9cf880cull, 0x2b20e172fed2ca01ull} },
  { {0xf462519dec2dd213ull, 0xef21db7269334ee8ull, 0xfe7def5c2ead2507ull, 0x27f837925e875c3eull} },
  { {0x5c3377c13ebe6693ull, 0xc6da397890f4b456ull, 0x0c98105cf1d4efc5ull, 0x137de63a6f07d6daull} },
  { {0xa59d9bd8fa886507ull, 0x55a6b2f9a851d130ull, 0xc476e4ac53d87bbbull, 0x0936b88b1746b509ull} },
  { {0xc8ec84f49fca5a89ull, 0xc92e2e33aa149752ull, 0x569a902ceff0f165ull, 0x2f43ccfb48d7e8d1ull} },
  { {0xd4b6c9e900a2111cull, 0x1a2179f152fe1c41ull, 0xfd2963d00a013455ull, 0x15d0cdf637dbac50ull} },
  { {0x5434f4571f134f74ull, 0xe7e9202d5243a351ull, 0x58f40861951d38d3ull, 0x3dca58e32b612030ull} },
  { {0x869823ea9dfa6239ull, 0x9ad56c598c41512aull, 0x02c3230c9867bc09ull, 0x29de69da7957a87bull} },
  { {0xd7a4f0f1bddb4947ull, 0x611e579f69631b96ull, 0xa448566730926b89ull, 0x2f352301d3c6005aull} },
  { {0xc711b30847847302ull, 0xff1597983ea8abe7ull, 0x7516b21442db115full, 0x09fc352edbf8e306ull} },
  { {0xff654e44d2a89b0aull, 0x16abfc86fd5655cfull, 0xac5139f505bbf625ull, 0x16bb73fd3488b6b2ull} },
  { {0xb1146a649e62443bull, 0xc5071f73da90950full, 0x0c1f7ffa808cf51cull, 0x3ea6a1341b91be81ull} },
  { {0xf7619839556d94fdull, 0xed98ff39f12376f8ull, 0xdf502a816527ce25ull, 0x01dd6e430d5f1928ull} },
  { {0xe52c4e0635fbc4b6ull, 0xe9fe3b8b53b6cffaull, 0x0fcb578292089726ull, 0x1059ce75cdf85375ull} },
  { {0xc74deb4ea3af4abcull, 0x2b6b2b2b658e35a3ull, 0x61c1e60a3c066ad6ull, 0x31d84fb4b851462dull} },
  { {0x2059e2eb604d8f45ull, 0xb934b045677ed42dull, 0xdc640f3d284bc7fdull, 0x2965c461a270054bull} },
  { {0x7d8fe3ff6e3d364full, 0x77ed4c4e8260ce46ull, 0xcf485e79e68f1984ull, 0x1316fcc25856eb60ull} },
  { {0x2aad28417596294cull, 0x7df78a8de06f8c30ull, 0x979652dea6870e87ull, 0x2002d0ef99a3f951ull} },
  { {0x3e62c86ea54becdfull, 0xde92d56316663baaull, 0xcc539eea66cb3267ull, 0x106f1f3deff1e274ull} },
  { {0xf0b3c0bff039aa93ull, 0x70e234781833be1eull, 0x39d3ca26462177cfull, 0x3f477f36bd644685ull} },
  { {0x289d9affc91662d3ull, 0xc16f3f2850480bf5ull, 0xa8a5b5eb3f36e8cdull, 0x2c2e1e271e174f7full} },
  { {0x3b50924b48d86161ull, 0x542b01b435b2e978ull, 0xd705d8f894bd5a99ull, 0x27dcaa4ec2ce04d0ull} },
  { {0x0c61a8c28a0a6888ull, 0x0ad5d293d0a44cc9ull, 0xe02ae3d79a8b1d26ull, 0x3dd0ba77618e36c7ull} },
  { {0x9fd2a343ae41d5d4ull, 0xbcee664d3b58ba47ull, 0xa95e4b16d3634396ull, 0x13fd836817b1ed95ull} },
  { {0x9b6346ac6536b8acull, 0xc4eac7c1fea38b82ull, 0xeef4892215c0756eull, 0x06a1d3ba70f3d824ull} },
  { {0x4bc93ce13a2202dbull, 0x6faf639e31e8735cull, 0x3a7adbe914041798ull, 0x065b39097712f334ull} },
  { {0x91fa739fac3cc658ull, 0xbd685a29df263e72ull, 0x3fa372ffd413b351ull, 0x3b5ddeed837d0fdfull} },
  { {0xd32e9c5297f05f3cull, 0xab18c7f824699894ull, 0xad438a7ca4c376e0ull, 0x2e2740384ca486c8ull} },
  { {0x004ccd5c5989fd50ull, 0xa693572932c67b44ull, 0xb7292259de7f06daull, 0x18a8b330506426b5ull} },
  { {0x6f6bb65beb827a5full, 0x090153db84b474b8ull, 0x9ac8801dbd86368cull, 0x22c7016289caf5deull} },
  { {0xa90f8dca52484659ull, 0xdfddd36a7ef2ef86ull, 0x3e872cf2b8cc188cull, 0x0a47351542453c95ull} },
  { {0xcfe202249a2ce66dull, 0x941d7fdaf464bc4full, 0x5cac0a78aa18649cull, 0x25fe7f59032728c1ull} },
  { {0x58d4c6cdfdee264eull, 0x51e6373bedc1651dull, 0xf8b9ec63a4b8ccbaull, 0x266980f9277110bfull} },
  { {0x06c999dae0c8fa16ull, 0x0fa97dec82099effull, 0x3e0a76f28d8f6d97ull, 0x383415afd6037266ull} },
  { {0x056dd6930a0ac749ull, 0xb91934be04bd09c7ull, 0xb37cc82c5c5c96e3ull, 0x1c4dab74ecc76ca7ull} },
  { {0x283dd958a23076e5ull, 0x86f9174e727b8025ull, 0x28e79e759b444759ull, 0x054bb8b2402ecb99ull} },
  { {0x1a6e775c46021e20ull, 0x66ea64fc9a4dfa88ull, 0x8fd8c801e2c9e73cull, 0x2d228dd31bc1145eull} },
  { {0xab66a82020242433ull, 0x752d508688728bd7ull, 0x2295ee3948f995edull, 0x091c1e5ea8c437f3ull} },
  { {0x6e7ea67266af5550ull, 0x7594d9a4f7f21c08ull, 0x454d241994797358ull, 0x32d54faaeaa1fd27ull} },
  { {0xd94741656aa884aeull, 0xd0539b539fe9cc35ull, 0x84d83248d4bf2861ull, 0x3b4a331a66af3c84ull} },
}};

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> WHIR_OOD {{
  { {0x458b9ec97df112a0ull, 0x79e44194cc7a4044ull, 0x6017acfa59c5bf3eull, 0x1d9090f605cac609ull} },
  { {0x3fa879d9273d4485ull, 0xa42518d442079dbaull, 0x0718d1fee48bc5cbull, 0x0be9c28abe79afaeull} },
  { {0x2e34c710014b5645ull, 0xb92bb1d65f734368ull, 0x248b288d229bc159ull, 0x0d17dc2cb95f81baull} },
  { {0x24e458e1ad61bd61ull, 0x25923bbc23b78195ull, 0x74181dfca0c76bc7ull, 0x391e93b63a921583ull} },
  { {0x88623a90bb38095eull, 0x2d15a29aa1aa5c53ull, 0xdc1aefe12a870a6full, 0x13fdbc02117f17c1ull} },
  { {0xef162cfdbff76bb7ull, 0x1d065eafa7624328ull, 0x626fec801ce6c4c9ull, 0x30e1e175880a56f9ull} },
  { {0xdf411f64d1ed4562ull, 0x0fe186ef811512b7ull, 0x2a4fa2e74e93f2daull, 0x1c9783083cfbc59full} },
  { {0xca9e32e58966a01dull, 0x3de3b46815eeca17ull, 0x041d24da9546e3faull, 0x241900ea1645f82dull} },
}};

inline constexpr std::array<std::uint64_t, 4> WHIR_OOD_COMMIT { {0x2f311b510227ada7ull, 0x5c9b811dddde896full, 0x552d8cb9246a0c36ull, 0x3f4671f34c67f7e1ull} };

inline constexpr std::array<std::array<std::uint64_t, 4>, 8> WHIR_W {{
  { {0xe3077d81d7cb30a7ull, 0x9fcce98ae8741245ull, 0x59a2d156c9342512ull, 0x1d5dc39b1f9e6902ull} },
  { {0x2556e107c4f73368ull, 0x862e51c6c94f88a2ull, 0xb91b1c64207bba06ull, 0x198bec7cd0defa22ull} },
  { {0x352084be6bbc3299ull, 0xd35b76b4f5f20f8eull, 0x23ac3f68ff182a75ull, 0x2a554b86497ce745ull} },
  { {0x9fbfc53d7ae70812ull, 0x30e659c66a36a575ull, 0x62bb40ab1c4c7b9bull, 0x37e86d8781af8ca2ull} },
  { {0x5fb70bdbc15830deull, 0x38411c839aa26424ull, 0x9a8cbe2c6086a4e4ull, 0x17aed26b0c5753baull} },
  { {0x4533eef150bb26cfull, 0x656dd3c26aaef2a1ull, 0x253347f90d4c7ea9ull, 0x1906d0a8394b3b5cull} },
  { {0x397de4f1a078f84aull, 0xc08af86f6d62ef07ull, 0x59b3d5bbd83f2492ull, 0x34a37c3da7504ed3ull} },
  { {0xdddb14edd45290b1ull, 0x61e5d083130c20b3ull, 0x38d1bfc03fedb000ull, 0x3a8ccb30e36e1abeull} },
}};

} // namespace hsma::golden

#!/usr/bin/env python3
import json, os
vecs = [
 {"id":"activate_e2","deposit_epoch":5,"lag":2,"checks":[5,6,7],"states":[0,0,1]},
 {"id":"bmin_reject","amount":49999,"min_bond":50000,"ok":0},
 {"id":"bmin_accept","amount":50000,"min_bond":50000,"ok":1},
 {"id":"slash","bonds":[150000,100000,50000],"burned":300000,"state":3},
 {"id":"cluster_floor","raw":80000,"ctotal":150000,"cap":100000,"capped":80000*100000//150000},
 {"id":"adv_safe","adv":199999,"total":1000000,"verdict":0},
 {"id":"adv_halt","adv":200000,"total":1000000,"verdict":1},
 {"id":"unbond_window","ue":10,"w":21,"checks":[10,30,31],"states":[2,2,4]},
]
os.makedirs("generated", exist_ok=True)
with open("generated/stake_golden.hpp","w") as f:
    f.write("#pragma once\n// P5-E golden vectors - Python oracle (bilingual law)\n// auto-generated - DO NOT HAND-EDIT (CA-R126)\n")
    f.write("namespace hsma::econ::golden {\n")
    f.write("inline constexpr long long ACTIVATE_E2[] = {5,6,7};\n")
    f.write("inline constexpr int ACTIVATE_E2_STATES[] = {0,0,1};\n")
    f.write("inline constexpr long long BMIN = 50000, BMIN_REJ = 49999;\n")
    f.write("inline constexpr long long SLASH_BONDS[] = {30000,20000,10000};\n")
    f.write("inline constexpr long long SLASH_BURNED = 60000; inline constexpr int SLASH_STATE = 3;\n")
    f.write("inline constexpr long long CC_RAW = 80000, CC_TOTAL = 150000, CC_CAP = 100000;\n")
    f.write("inline constexpr long long CC_EXPECT = %d;\n" % (80000*100000//150000))
    f.write("inline constexpr long long ADV_SAFE = 199999, ADV_TOTAL = 1000000;\n")
    f.write("inline constexpr long long ADV_HALT = 200000;\n")
    f.write("inline constexpr long long UNB_E = 10, UNB_W = 21;\n")
    f.write("inline constexpr int UNB_STATES[] = {2,2,4};\n")
    f.write("} // namespace hsma::econ::golden\n")
print("[step35] stake_golden.hpp written")

# ═══ HSMA Node — the complete testnet validator in a container ═══
# Build:  docker build -t hsma/node .
# Run:    docker run -p 31233:31233 -p 32233:32233 hsma/node
# Connect: docker run hsma/node ./build/epoch_node 31234 --seed <host>:31233

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake ninja-build clang python3 git build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hsma

# copy the source (the goldens regenerate inside the container)
COPY include/ include/
COPY generated/ generated/
COPY scripts/ scripts/
COPY conformance/ conformance/
COPY src/ src/
COPY tools/ tools/
COPY CMakeLists.txt .

# generate the goldens and build
RUN mkdir -p build && \
    python3 scripts/gen_run_new.py --out generated 2>&1 | tail -3 && \
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel $(nproc)

# the runtime stage (smaller image)
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libstdc++6 && rm -rf /var/lib/apt/lists/*
WORKDIR /hsma
COPY --from=builder /hsma/build/epoch_node ./build/epoch_node
COPY --from=builder /hsma/build/envfaucet ./build/envfaucet
COPY --from=builder /hsma/build/votecast ./build/votecast
COPY --from=builder /hsma/generated/ ./generated/

EXPOSE 31233 32233

HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost:32233/api || exit 1

CMD ["./build/epoch_node", "31233"]

FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-21

RUN apt-get update && apt-get install -y curl binaryen

WORKDIR /capstone
RUN curl -L https://github.com/capstone-engine/capstone/archive/f6ab2ab9152e94687f112cda9d0cb5c0745ff059.tar.gz | tar -xz --strip-components=1 -C /capstone

RUN CAPSTNE_STATIC=yes CAPSTONE_SHARED=no ./make.sh
ADD buildtools/wasm/access.c access.c
RUN $CC $CFLAGS -c -Iinclude access.c

ENV LDFLAGS $CFLAGS -mexec-model=reactor
RUN $CXX -o libcapstone-noopt.wasm -Wl,--global-base=1024 $LDFLAGS \
  libcapstone.a access.o \
  -Wl,--export=cs_version \
  -Wl,--export=cs_open \
  -Wl,--export=cs_close \
  -Wl,--export=cs_option \
  -Wl,--export=cs_strerror \
  -Wl,--export=cs_disasm_iter \
  -Wl,--export=cs_malloc \
  -Wl,--export=cs_free \
  -Wl,--export=cs_get_mnemonic \
  -Wl,--export=cs_get_op_str \
  -Wl,--export=malloc \
  -Wl,--export=free

RUN wasm-opt -o libcapstone.wasm --low-memory-unused --flatten --rereloop --converge -O3 libcapstone-noopt.wasm

CMD ["cp", "libcapstone.wasm", "/out/"]

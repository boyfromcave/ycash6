package=native_clang
# To update the Clang compiler:
# - Change the versions below, and the MSYS2 version in libcxx.mk
# - Run the script ./contrib/devtools/update-clang-hashes.sh
# - Manually fix the versions for packages that don't exist (the LLVM project
#   doesn't uniformly cut binaries across releases).
# The Clang compiler should use the same LLVM version as the Rust compiler.
# LEGACY_GLIBC build (opt-in): set LEGACY_GLIBC=1 to fetch the Clang 18.1.8
# binary built for Ubuntu 18.04 (glibc 2.27) instead of the default Clang 22.
# Use this only when building inside an old (e.g. Ubuntu 18.04) environment to
# produce ycashd binaries that run on those old glibc systems (3rd-party
# integrators on legacy distros). The default Clang 22 binary requires glibc
# 2.34 to run and its output requires glibc 2.38, so it neither runs on nor
# targets 18.04. Rust stays at 1.96 (its binary runs on glibc 2.17); the
# resulting Clang18<->Rust-LLVM22 mismatch is harmless here because only
# Rust-internal thin-LTO is used, not cross-language C++/Rust LTO.
ifeq ($(LEGACY_GLIBC),1)
$(package)_default_major_version=18
$(package)_default_version=18.1.8
else
$(package)_default_major_version=22
$(package)_default_version=22.1.7
endif
# 2024-05-03: No Intel macOS packages are available for Clang 16, 17, or 18.
# x86_64-apple-darwin is being abandoned; only aarch64-darwin is maintained.
$(package)_major_version_darwin=15
$(package)_version_darwin=15.0.4
# 2023-02-16: No FreeBSD packages are available for Clang 15.
# 2023-04-07: Still the case.
# 2024-05-03: No FreeBSD packages are available for Clang 17 or 18.
#             Clang 16 has FreeBSD 13 packages, but none for FreeBSD 12.
$(package)_major_version_freebsd=14
$(package)_version_freebsd=14.0.6

# Tolerate split LLVM versions. If an LLVM build is not available for a Tier 3
# platform, we permit an older LLVM version to be used. This means the version
# of LLVM used in Clang and Rust will differ on these platforms, preventing LTO
# from working.
$(package)_version=$(if $($(package)_version_$(host_arch)_$(host_os)),$($(package)_version_$(host_arch)_$(host_os)),$(if $($(package)_version_$(host_os)),$($(package)_version_$(host_os)),$($(package)_default_version)))
$(package)_major_version=$(if $($(package)_major_version_$(host_arch)_$(host_os)),$($(package)_major_version_$(host_arch)_$(host_os)),$(if $($(package)_major_version_$(host_os)),$($(package)_major_version_$(host_os)),$($(package)_default_major_version)))

$(package)_download_path_linux=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
ifeq ($(LEGACY_GLIBC),1)
# Clang 18.1.8 binary built for Ubuntu 18.04 (glibc 2.27) — runs on old distros.
$(package)_download_file_linux=clang+llvm-$($(package)_version)-x86_64-linux-gnu-ubuntu-18.04.tar.xz
$(package)_file_name_linux=clang-llvm-$($(package)_version)-x86_64-linux-gnu-ubuntu-18.04.tar.xz
$(package)_sha256_hash_linux=54ec30358afcc9fb8aa74307db3046f5187f9fb89fb37064cdde906e062ebf36
else
$(package)_download_file_linux=LLVM-$($(package)_version)-Linux-X64.tar.xz
$(package)_file_name_linux=LLVM-$($(package)_version)-Linux-X64.tar.xz
$(package)_sha256_hash_linux=edb0522b41e261819c06ea437d249f9b8acfa413d3805bc9920eec6fb76ff830
endif
$(package)_download_path_darwin=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
$(package)_download_file_darwin=clang+llvm-$($(package)_version)-x86_64-apple-darwin.tar.xz
$(package)_file_name_darwin=clang-llvm-$($(package)_version)-x86_64-apple-darwin.tar.xz
$(package)_sha256_hash_darwin=4c98d891c07c8f6661b233bf6652981f28432cfdbd6f07181114195c3536544b
# aarch64-darwin resolves to the darwin pin (Clang 15.0.4), not default_version,
# because the os-only `darwin` override is matched before default. The native
# Mac build compiles with the system (Xcode) clang anyway; this fetched clang is
# only for staged aux tools / libc++, so it is intentionally NOT bumped to 22.1.7
# (and 15.0.4 predates the LLVM-*-macOS-ARM64 naming, using clang+llvm-*).
$(package)_download_file_aarch64_darwin=clang+llvm-$($(package)_version)-arm64-apple-darwin21.0.tar.xz
$(package)_file_name_aarch64_darwin=clang-llvm-$($(package)_version)-arm64-apple-darwin.tar.xz
$(package)_sha256_hash_aarch64_darwin=70e7a6d98fc42d4c36aca1a5b666c57e83ae474df5920382853b9209c829938a
$(package)_download_path_freebsd=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
$(package)_download_file_freebsd=clang+llvm-$($(package)_version)-amd64-unknown-freebsd12.tar.xz
$(package)_file_name_freebsd=clang-llvm-$($(package)_version)-amd64-unknown-freebsd12.tar.xz
$(package)_sha256_hash_freebsd=b0a7b86dacb12afb8dd2ca99ea1b894d9cce84aab7711cb1964b3005dfb09af3
$(package)_download_path_aarch64_linux=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
$(package)_download_file_aarch64_linux=LLVM-$($(package)_version)-Linux-ARM64.tar.xz
$(package)_file_name_aarch64_linux=LLVM-$($(package)_version)-Linux-ARM64.tar.xz
$(package)_sha256_hash_aarch64_linux=118ca2d3ad9da34367e05735317854e7977db45dc4c02a32af58da64c23b8789

ifeq ($(build_os),linux)
ifeq ($(LEGACY_GLIBC),1)
# The Clang 18.1.8 ubuntu-18.04 ld.lld does not need libxml2 staged.
$(package)_dependencies=native_libtinfo5
else
# native_libxml2 supplies libxml2.so.2, which the downloaded ld.lld/lld link
# against; depending on it here stages the library before any host package links.
$(package)_dependencies=native_libtinfo5 native_libxml2
endif
endif

# Ensure we have clang native to the builder, not the target host. Prefer the
# arch-specific entry (e.g. aarch64_darwin) over the os-only one so an arm64
# build host gets a native clang instead of an x86_64 one under Rosetta.
ifneq ($(canonical_host),$(build))
$(package)_exact_download_path=$(if $($(package)_download_path_$(build_arch)_$(build_os)),$($(package)_download_path_$(build_arch)_$(build_os)),$($(package)_download_path_$(build_os)))
$(package)_exact_download_file=$(if $($(package)_download_file_$(build_arch)_$(build_os)),$($(package)_download_file_$(build_arch)_$(build_os)),$($(package)_download_file_$(build_os)))
$(package)_exact_file_name=$(if $($(package)_file_name_$(build_arch)_$(build_os)),$($(package)_file_name_$(build_arch)_$(build_os)),$($(package)_file_name_$(build_os)))
$(package)_exact_sha256_hash=$(if $($(package)_sha256_hash_$(build_arch)_$(build_os)),$($(package)_sha256_hash_$(build_arch)_$(build_os)),$($(package)_sha256_hash_$(build_os)))
endif

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/bin && \
  rm -r include/flang && \
  rm -r include/lldb && \
  rm lib/libflang* && \
  rm lib/libFortran* && \
  rm lib/liblldb* && \
  cp bin/clang-$($(package)_major_version) $($(package)_staging_prefix_dir)/bin && \
  cp bin/lld $($(package)_staging_prefix_dir)/bin && \
  cp bin/llvm-ar $($(package)_staging_prefix_dir)/bin && \
  cp bin/llvm-config $($(package)_staging_prefix_dir)/bin && \
  cp bin/llvm-nm $($(package)_staging_prefix_dir)/bin && \
  cp bin/llvm-objcopy $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/clang $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/clang++ $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/ld.lld $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/ld64.lld $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/lld-link $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/llvm-ranlib $($(package)_staging_prefix_dir)/bin && \
  cp -P bin/llvm-strip $($(package)_staging_prefix_dir)/bin && \
  (test ! -f include/$(build_arch)-unknown-linux-gnu/c++/v1/__config_site || \
   cp include/$(build_arch)-unknown-linux-gnu/c++/v1/__config_site include/c++/v1/__config_site) && \
  mv include/ $($(package)_staging_prefix_dir) && \
  mv lib/ $($(package)_staging_prefix_dir) && \
  mv libexec/ $($(package)_staging_prefix_dir)
endef

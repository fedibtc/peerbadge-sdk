{ pkgs, ... }:

{
  cachix.enable = false;

  env.CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_24;
    pnpm = {
      enable = true;
      install.enable = true;
    };
  };

  packages = with pkgs; [
    binaryen
    llvmPackages.clang
    wasm-bindgen-cli
    wasm-pack
  ];
}

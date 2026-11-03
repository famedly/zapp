# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: Apache-2.0

{ inputs, ... }: {
  perSystem =
    { config, pkgs, ... }:
    let
      mkZapp =
        rustPlatform:
        rustPlatform.buildRustPackage {
          pname = "zapp";
          version = (pkgs.lib.importTOML ../Cargo.toml).package.version;

          src = pkgs.lib.fileset.toSource {
            root = ../.;
            fileset = pkgs.lib.fileset.unions [
              ../Cargo.toml
              ../Cargo.lock
              ../build.rs
              ../src
            ];
          };

          cargoLock.lockFile = ../Cargo.lock;

          # ensure that the flake is always built from a clean tree, so
          # the binary contains the correct commit hash to fulfill AGPL requirements
          env.GIT_COMMIT_HASH = inputs.self.rev;

          # the tests build HTTP clients, which load the system's trusted roots;
          # the build sandbox has none
          env.SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

          meta = {
            description = "Zitadel Automatic Project Provisioner";
            mainProgram = "zapp";
          };
        };
    in
    {
      packages = {
        zapp = mkZapp pkgs.pkgsStatic.rustPlatform;
        default = config.packages.zapp;

        docker-image = pkgs.dockerTools.buildLayeredImage {
          name = "zapp";
          tag = "latest";

          config = {
            Entrypoint = [ (pkgs.lib.getExe config.packages.zapp) ];
            ExposedPorts."8080/tcp" = { };
          };
        };
      };
    };
}

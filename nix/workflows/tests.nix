# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: Apache-2.0

{ config, ... }:
let
  allowed-actions = config.famedly.standards.allowed-action-versions;
in
{
  perSystem.githubActions.workflows.tests = {
    name = "Run tests";

    on.pullRequest = {
      branches = [ "**" ];
      types = [
        "opened"
        "reopened"
        "synchronize"
        "ready_for_review"
      ];
    };
    on.mergeGroup = { };

    concurrency = {
      group = "\${{ github.workflow }}-\${{ github.ref }}";
      cancelInProgress = true;
    };

    jobs.nextest = {
      runsOn = "ubuntu-26.04-arm";

      steps = [
        { uses = allowed-actions."actions/checkout".uses; }
        { uses = allowed-actions."cachix/install-nix-action".uses; }

        {
          name = "Run tests";
          shell = "nix develop .#rust --command bash {0}";
          run = "cargo nextest run --all-targets --all-features";
        }
      ];
    };
  };
}

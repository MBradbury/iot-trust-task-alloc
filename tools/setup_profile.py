#!/usr/bin/env python3

import argparse

from tools.setup import Setup as BaseSetup, available_targets

class Setup(BaseSetup):
    def __init__(self, mode: str, target: str, verbose_make: bool, deploy: str):
        super().__init__(trust_model="basic",
                         trust_choose=None,
                         applications=["monitoring"],
                         with_pcap=False,
                         with_adversary=None,
                         defines={},
                         target=target,
                         verbose_make=verbose_make,
                         deploy=deploy)

        self.mode = mode
        self.binaries = ["profile"]

    def _target_build_args(self):
        build_args = super()._target_build_args()

        if self.mode == "AES":
            build_args["PROFILE_AES"] = 1
        elif self.mode == "ECC":
            build_args["PROFILE_ECC"] = 1
        else:
            raise RuntimeError(f"Unknown profile mode {self.mode}")

        return build_args

    def _build_border_router(self):
        # Don't need this
        pass

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Setup')
    parser.add_argument('mode', choices=['ECC', 'AES'], help='What to profile')
    parser.add_argument('--target', choices=available_targets, default=available_targets[0], help="Which target to compile for")
    parser.add_argument('--verbose-make', action='store_true', help='Outputs greater detail while compiling')
    parser.add_argument('--deploy', choices=['none', 'ansible', 'fabric'], default='none', help='Choose how deployment is performed to observers')
    args = parser.parse_args()

    setup = Setup(args.mode,
                  args.target,
                  args.verbose_make,
                  args.deploy)
    setup.run()

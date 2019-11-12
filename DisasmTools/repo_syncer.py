"""
:author Lan: This module is responsible for syncing data between the repository and IDA.
- Replace specific functions/data in the repository, or to sync them given specific configurations
so that a redump is not made, preserving the source's style and comments.
- Sync the repository into IDA, creating/changing label names and functions/data.
"""

import source_sync as ss
import Definitions.Environment as Env

def main():
    env = Env.env
    return ss.read_repo(env['projPath'], 'bn6f.elf', ['rom.s'], info=True)

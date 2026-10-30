"""Explicit bootstrap/inspection for the separate native Game graph fetcher.

The native Library submits requests. This adapter never imports recipient graph
bytes, schedules node/range acquisition or grants execution approval.
"""
import argparse
import json
from pathlib import Path
import live
import nodes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('start')
    start.add_argument('--package', type=Path, required=True)
    start.add_argument('--public', type=Path, required=True)
    start.add_argument('--release-id', required=True)
    args = parser.parse_args(argv)
    client = live.Client(args.socket, timeout=180)
    try:
        config = nodes.approved_package(args.package, args.public, args.release_id, 1151)
        instance = nodes.start_package(client, config, nodes.validate_package(config))
    finally:
        client.close()
    print(json.dumps(dict(instance=instance, release_id=args.release_id, rights=1151,
        submission='native selected Library incarnation only; SDK710/711/712',
        local_execution_approved=False), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

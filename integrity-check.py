import argparse
import base64
import hashlib
import hmac
import os
import pathlib
import time
from rich.prompt import Confirm
from rich import print


def argument():
    parser = argparse.ArgumentParser(
        prog='Python Integrity Check',
        description='🔍 This script checks whether your file has been tampered with. '
                    'It is recommended to keep a copy of the hash file in a safe place.',
        epilog='📜 For more help, refer to the documentation.'
    )

    parser.add_argument('-d', '--destination',
                        help='📁 Specify where to store your hash file (default: current directory).',
                        type=str,
                        default='./')

    parser.add_argument('-s', '--source',
                        help='📄 Specify the file you want to hash (required).',
                        type=str,
                        required=True)

    parser.add_argument('-c', '--create',
                        help='🛠️ Create a hash file for the specified source file.',
                        action='store_true')

    parser.add_argument('--check',
                        help='🔒 Check the integrity of the specified file using its hash.',
                        action='store_true')

    parser.add_argument('--dhash',
                        help='🔑 Provide the hex digest for integrity checking.',
                        type=str)

    return parser.parse_args()


def hashfile(source_path: str):
    try:
        stat = os.stat(source_path)
        metadata = base64.b64encode(time.ctime(stat.st_mtime).encode() +
                                    time.ctime(stat.st_ctime).encode() +
                                    time.ctime(stat.st_atime).encode())
        hss = hashlib.sha256()
        hss.update(metadata)
        with open(source_path, 'rb') as h_file:
            for chunk in iter(lambda: h_file.read(4096), b""):
                hss.update(chunk)
        return hss.digest()
    except FileNotFoundError:
        print(f'[bold red]:cross_mark: {pathlib.Path(source_path).name}[/bold red] The file was not found. Please '
              f'check the path and try again.')
        return None
    except Exception as e:
        print(f'[bold red]:cross_mark: An unexpected error occurred: {e}')
        return None


def savefile(destination_path: str, data: bytes):
    try:
        with open(destination_path, 'xb') as f:
            f.write(data)
        print(f'[bold green]:white_heavy_check_mark:{pathlib.Path(destination_path).name}[/bold green] The file has '
              f'been created successfully.')
    except FileExistsError:
        print(f'[bold red]:warning: The file {pathlib.Path(destination_path).name} '
              f'already exists.')
        yn = Confirm.ask("Do you want to overwrite it?", default=False)
        if yn:
            with open(destination_path, 'wb') as f:
                f.write(data)
            print(f'[bold green]:white_heavy_check_mark: {pathlib.Path(destination_path).name}[/bold green] The file '
                  f'has been successfully overwritten.')
        else:
            print(f'[bold red]:warning: {pathlib.Path(destination_path).name}[/bold red] The file has not been saved. '
                  f'Please check your options.')


def integrity_check(source_path: str, destination_path: str):
    h_file1 = hashfile(source_path)
    if h_file1 is None:
        return None
    try:
        with open(destination_path, 'rb') as d_file:
            h_file2 = d_file.read()
        return hmac.compare_digest(h_file1, h_file2)
    except FileNotFoundError:
        print(f'[bold red]:cross_mark: {pathlib.Path(destination_path).name}[/bold red] The file was not found. Please '
              f'check the path and try again.')
        return None


if __name__ == "__main__":
    args = argument()
    if args.check:
        check = integrity_check(args.source, args.destination)
        if check is True:
            print('[bold green]:white_heavy_check_mark: File Status:[/bold green] The file is okay and has not been '
                  'tampered with. :party_popper: :partying_face:')
        elif check is False:
            print('[bold red]:warning: File Status:[/bold red] Warning! The file has been tampered with. '
                  '[bold yellow]:warning:[/bold yellow] :boom:')
        else:
            print('[bold]:cross_mark: Oops! Something went wrong. Please try again! :thinking_face:')

    if args.create:
        hash_file = hashfile(args.source)
        if hash_file is None:
            print('[bold]:cross_mark: Oops! Something went wrong. Please try again! :thinking_face:')
        else:
            savefile(args.destination, hash_file)

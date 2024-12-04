import argparse
import base64
import hashlib
import hmac
import os
import pathlib
import time


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
        print(f'❌ Error: The file "{pathlib.Path(source_path).name}" was not found. '
              f'Please check the path and try again.')
        return None
    except Exception as e:
        print(f'❌ An unexpected error occurred: {e}')
        return None


def savefile(destination_path: str, data: bytes):
    try:
        with open(destination_path, 'xb') as f:
            f.write(data)
        print(f'✅ The file "{pathlib.Path(destination_path).name}" has been created successfully.')
    except FileExistsError:
        print(f'The file "{pathlib.Path(destination_path).name}" already exists.')
        yn = input('Do you want to overwrite it? (y/N): ')
        if yn in ('y', 'Y'):
            with open(destination_path, 'wb') as f:
                f.write(data)
            print(f'✅ The file {pathlib.Path(destination_path).name} has been successfully overwritten.')
        else:
            print('❌ The file has not been saved. Please check your options.')


def integrity_check(source_path: str, destination_path: str):
    h_file1 = hashfile(source_path)
    if h_file1 is None:
        return None
    try:
        with open(destination_path, 'rb') as d_file:
            h_file2 = d_file.read()
        return hmac.compare_digest(h_file1, h_file2)
    except FileNotFoundError:
        print(f'❌ Error: The file "{pathlib.Path(destination_path).name}" was not found. '
              f'Please check the path and try again.')
        return None


if __name__ == "__main__":
    args = argument()
    if args.check:
        check = integrity_check(args.source, args.destination)
        if check is True:
            print('✅ File Status: The file is okay and has not been tampered with. 🎉')
        elif check is False:
            print('❌ File Status: Warning! The file has been tampered with. ⚠️')
        else:
            print('❌ Oops! Something went wrong. Please try again! 😅')

    if args.create:
        hash_file = hashfile(args.source)
        if hash_file is None:
            print('❌ Oops! Something went wrong. Please try again! 😅')
        else:
            savefile(args.destination, hash_file)

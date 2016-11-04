import argparse
import os
import sys
import logging
from os import listdir
from os.path import isfile, join


logger = logging.getLogger(__name__)


def get_file_list(input):
    file_list = []

    if input is not None:
        for c_input in input:
            if os.path.isfile(c_input):
                file_list.append(c_input)
            else:
                file_list += [f for f in listdir(c_input) if isfile(join(c_input, f))]

    return file_list


def transform_in_to_out(csv_arr):
    n = csv_arr[1]
    n_long = long(n, 16)
    return [str(n_long), str(n_long % 3)]


# Main - argument parsing + processing
def main():
    parser = argparse.ArgumentParser(description='NN dataset generator')
    parser.add_argument('-o', '--out', dest='outfile', default='tmp_out.csv',
                        help='Output file')
    parser.add_argument('-s', '--separator', dest='separator', default=';',
                        help='CSV separator')
    parser.add_argument('--header', dest='header', type=int, default=1,
                        help='Header is present? Yes by default')
    parser.add_argument('input', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='dirs/files to process')

    args = parser.parse_args()

    # Read directory, get file name list.
    all_files = get_file_list(args.input)
    if len(all_files) == 0:
        parser.print_usage()
        sys.exit(1)

    # Per file
    with open(args.outfile, 'w') as fo:
        for idx, cur_file in enumerate(all_files):
            # File existence check
            if not os.path.exists(cur_file):
                raise('File %s not found' % cur_file)

            logger.info(' - Processing file [%02d/%02d]: %s' % (idx+1, len(all_files), cur_file))

            # Read the input file, line by line, process
            with open(cur_file, 'r') as fr:
                lines = -1
                while True:
                    lines += 1
                    cur_line = fr.readline()
                    if len(cur_line) == 0:
                        break

                    if args.header and lines == 0:
                        continue

                    if args.separator not in cur_line:
                        continue

                    csv_line = cur_line.strip().split(args.separator)
                    out_csv_line = transform_in_to_out(csv_line)

                    # dump to the output file
                    fo.write(args.separator.join(out_csv_line) + '\n')

                pass  # line-by-line read
            pass  # with source file
        pass  # for each source file
    pass  # with output file


# Launcher
if __name__ == "__main__":
    main()


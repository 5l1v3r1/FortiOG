from argparse import ArgumentParser
from tkinter import filedialog, Tk
from os import getcwd
from ipaddress import IPv4Network


def main():
    """ Main Program """

    parser = ArgumentParser(
        description='Provided a list of IP addresses or URL\'s, format the proper fortigate commands to create them '
                    'and output to a file within the current working directory. DISCLAIMER: If you run something on '
                    'an NSD that you shouldn\'t have, we are NOT responsible. READ YOUR CODE BEFORE YOU PLACE IT.')
    parser.add_argument('VDOM', help='Specify the VDOM to which changes will be applied.')
    parser.add_argument(
        '--File', help='Specify a file. Each entry should be on its own line, and have no additional characters. If '
                       'no file is given, the file explorer will prompt you to select one.')
    args = parser.parse_args()

    # If file argument is not given, open file explorer.
    if args.File:
        array = withopen(args.File)
    else:
        array = withopen(askopenfilename())

    with open(args.VDOM + '.txt', 'w') as output_file:
        output_file.write('config vdom\n')
        output_file.write('edit %s\n' % str(args.VDOM))
        output_file.write('config firewall address\n')

        # If valid IP, generate an IP address object. If not, generate URL.
        for i in range(0, len(array)):
            try:
                ip_addr = IPv4Network(array[i])
                generateip(ip_addr, output_file)
            except ValueError:
                url = array[i]
                generateurl(url, output_file)

        print('Your file has been saved to ' + getcwd())


def askopenfilename():
    """
    Opens file explorer to select an input file.
    """
    root = Tk()
    root.withdraw()  # Prevents empty root window from displaying.
    file_path = filedialog.askopenfilename()
    return file_path


def withopen(file):
    """
    Turn an input_file into a properly formatted list.

    file -- Input text file. Defined via command line argument or graphical file explorer.
    """
    try:
        with open(file, 'r') as input_file:
            array = input_file.read().splitlines()
        return array
    except FileNotFoundError:
        print('No file selected.')
        exit()


def generateip(ip_addr, output_file):
    """
    Generate a single IP address object.

    ip_addr -- IP address network object
    output_file -- an output text file
    """
    output_file.write('edit \'%s\'\n' % str(ip_addr.with_prefixlen))
    output_file.write('set color 1\n')
    output_file.write('set subnet %s %s\n' %
                      (str(ip_addr.network_address), str(ip_addr.netmask)))
    output_file.write('next\n\n')


def generateurl(url, output_file):
    """
    Generate a single URL address object.

    url -- A valid URL string
    output_file -- an output text file
    """

    output_file.write('edit %s\n' % url)
    output_file.write('set color 1\n')
    output_file.write('set type fqdn\n')
    output_file.write('set fqdn %s\n' % url)
    output_file.write('next\n\n')


if __name__ == '__main__':
    main()


# TO DO:
# Add UPX Compression
# Add to PATH
# Run from

from argparse import ArgumentParser, RawTextHelpFormatter
from ipaddress import IPv4Network
from re import compile


def Main():
    """ Main Prgram """

    parser = ArgumentParser(
        description='Provided a list of IP addresses or URL\'s, format the proper fortigate commands to create them '
                    'and output to a file within the current working directory. DISCLAIMER: If you run something on '
                    'a firewall that you shouldn\'t have, we are NOT responsible. READ YOUR CODE BEFORE YOU PLACE IT.',
        formatter_class = RawTextHelpFormatter)
    parser.add_argument(
        'VDOM', help='Specify the VDOM to which changes will be applied.\n\n')
    parser.add_argument(
        'File', help='Accepts two kinds of files, .txt & .csv. Each type should be formatted differently.\n'
        '.txt: Each entry should be on its own line, and have no additional characters, '
        ' formatted as IP/CIDR or a URL.\n'
        '.csv: Should consist of 4 fields.  The first is required, the rest are optional:\n\n'
        'IP/CIDR or URL (the CIDR prefix is optional, and just an IP can be accepted)\n'
        'Netmask (needed if you do not provide a CIDR in the previous field)\n'
        'Custom Name for the object\n'
        'Interface to attach object to\n\n'
        '.csv\'s should be formatted similarly to an Excel .csv')
    args = parser.parse_args()

    with open(args.File, 'r') as input_file:
        array = input_file.read().splitlines()

    with open(args.VDOM + '.txt', 'w') as output_file:
        output_file.write("config vdom\n")
        output_file.write("edit %s\n" % str(args.VDOM))
        output_file.write("config firewall address\n")

        for i in range(0, len(array)):
            generate_network_object(array[i], output_file)


def generate_network_object(ip_addr, output_file):
    """
    Attempts to generate a network object, which will be passed to the generate_ip function
    If an object appears to be an IP, but has a typo, the user will be prompted to provide an ip
    Otherwise creates a url entry.

    ip_addr -- Takes a value, used to generate a URL or IP object
    output_file -- The current file being written to
    """

    loop = True
    y_or_n = "n"
    ip_regex = compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

    while loop is True:
        #import pdb; pdb.set_trace()
        try:
            ip_addr = IPv4Network(ip_addr)
            generate_ip(ip_addr, output_file)
            loop = False
        except ValueError:
            if ip_regex.search(ip_addr) is not None:
                y_or_n = input(
                    "Is " + ip_addr + " supposed to be an ip address? y | [n]: ") or "n"
            if y_or_n == "y":
                ip_addr = input(
                    "Please specify an IP/CIDR network address: ")
                generate_network_object(ip_addr, output_file)
            else:
                generate_url(ip_addr, output_file)
                loop = False


def generate_ip(ip_addr, output_file):
    """
    Generate a single IP address object.

    ip_addr -- IP address network object
    output_file -- an output text file
    """
    output_file.write("edit \"%s\"\n" % str(ip_addr.with_prefixlen))
    output_file.write("set color 1\n")
    output_file.write("set subnet %s %s\n" %
                      (str(ip_addr.network_address), str(ip_addr.netmask)))
    output_file.write("next\n\n")


def generate_url(url, output_file):
    """
    Generate a single URL address object.

    url -- A valid URL string
    output_file -- an output text file
    """

    output_file.write("edit %s\n" % url)
    output_file.write("set color 1\n")
    output_file.write("set type fqdn\n")
    output_file.write("set fqdn %s\n" % url)
    output_file.write("next\n\n")


if __name__ == '__main__':
    Main()

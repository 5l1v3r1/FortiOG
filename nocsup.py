from argparse import ArgumentParser
from ipaddress import IPv4Network


def Main():
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

    with open(args.File, 'r') as input_file:
        array = input_file.read().splitlines()

    with open(args.VDOM + '.txt', 'w') as output_file:
        output_file.write("config vdom\n")
        output_file.write("edit %s\n" % str(args.VDOM))
        output_file.write("config firewall address\n")

        for i in range(0, len(array)):
            try:
                ip_addr = IPv4Network(array[i])
                generateip(ip_addr, output_file)
            except ValueError:
                url = array[i]
                generateurl(url, output_file)

    print('Your file has been saved to /tmp')


def generateip(ip_addr, output_file):
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


def generateurl(url, output_file):
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

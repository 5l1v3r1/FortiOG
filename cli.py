#!/bin/python3
from argparse import ArgumentParser, RawTextHelpFormatter
from csv import reader
from re import compile as regex_create
from ipaddress import IPv4Network
from time import strftime


def Main():
    """ Main Prgram """
    # Parser for user CLI interaction
    parser = ArgumentParser(
        description='Provided a list of IP\'s or URL\'s, format the proper fortigate commands '
                    'to create them and output to a file within the current working directory.\n'
                    'DISCLAIMER: If you run something on a firewall that you shouldn\'t have, '
                    'we are NOT responsible. READ YOUR CODE BEFORE YOU PLACE IT!!!',
        usage='VDOM input_file.txt or .csv',
        formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        '-v', '--VDOM', help='Specify the VDOM to which changes will be applied.\n\n', default=False)
    parser.add_argument(
        'File', help='Accepts two kinds of files, .txt & .csv. '
        'Each type should be formatted differently.\n'
        '.txt: Each entry should be on its own line, formatted as IP/CIDR, IP/Netmask or a URL.\n'
        '.csv: Should consist of 5 fields.  The first is required, the rest are optional:\n\n'
        'IP/CIDR or URL (the CIDR prefix is optional, and just an IP can be accepted)\n'
        'Netmask (needed if you do not provide a CIDR in the previous field)\n'
        'Custom Name for the object\n'
        'Interface to associate object to\n'
        'Comment to label the object\n\n'
        '.csv\'s should be formatted similarly to an Excel .csv')
    ip_or_port = parser.add_mutually_exclusive_group()
    ip_or_port.add_argument('-i', '--ip', default=False, action='store_true',
                            help='Create address objects')
    ip_or_port.add_argument('-p', '--port', default=False, action='store_true',
                            help='Create customer service objects')
    args = parser.parse_args()

    txt_file = regex_create(r"\.txt")
    csv_file = regex_create(r"\.csv")

    # Check if the user submitted a csv or txt file
    if txt_file.search(args.File) is not None and args.ip is True:
        txt_mode(args.VDOM, args.File, 'ip')
    elif txt_file.search(args.File) is not None and args.port is True:
        txt_mode(args.VDOM, args.File, 'port')

    elif csv_file.search(args.File) is not None and args.ip is True:
        csv_mode(args.VDOM, args.File, 'ip')
    elif csv_file.search(args.File) is not None and args.port is True:
        csv_mode(args.VDOM, args.File, 'port')

    elif args.ip is False and args.port is False:
        print("Please specify -i or -p")
    else:
        print("Please retry with a valid file type")

# ------------------------------------------------------------------------------
#                           IP Address Objects
# ------------------------------------------------------------------------------


def txt_mode(vdom, file_in, mode):
    """
    Function created to handle simple text files

    vdom -- the user input vdom
    file_in -- the user input file
    mode -- Accepts 'ip' or 'port' for address or service objects
    """
    # Read in users list of parameters
    with open(file_in, 'r') as input_file:
        array = input_file.read().splitlines()

    # If the user did not provide a name, generate a timestamp to use as one
    # instead
    edit_vdom = True
    if vdom is False:
        vdom = strftime("%d-%m-%Y%_H:%M:%S")
        edit_vdom = False

    # Create a new file using the users parameters
    with open(vdom + '.txt', 'w') as output_file:
        if edit_vdom is False:
            header(vdom, output_file, mode, edit_vdom)
        else:
            header(vdom, output_file, mode)
        for element in array:
            # Address Groups
            if mode == 'ip':
                ip_addr = ip_check(element)

                # Create a name for an ip address, or use the users url string
                if ip_addr[1] == 'ip':
                    name = ip_addr[0].with_prefixlen
                else:
                    name = ip_addr[0]
                generate_name(name, output_file)

                # Generate an IP or URL, based on ip_check returning an ip
                if ip_addr[1] == 'ip':
                    generate_ip(ip_addr[0], output_file)
                    generate_end(output_file)
                else:
                    generate_url(ip_addr[0], output_file)
                    generate_end(output_file)

            # Service Groups
            elif mode == 'port':
                port = port_check(element)
                generate_name('tcp_udp_' + port, output_file, True)
                generate_service(output_file, 'tcp', port)
                generate_service(output_file, 'udp', port)
                generate_end(output_file)

    # Print the users created file
    with open(vdom + '.txt', 'r') as finished_file:
        print("")
        print(finished_file.read())


def csv_mode(vdom, file_in, mode):
    """
    Function created to handle csv files
    csv files should have 4 fields, the last 3 are optional:
    IP, netmask, name, interface

    vdom -- the user input vdom
    file_in -- the user input file
    mode -- Accepts 'ip' or 'port' for address or service objects
    """
    array = []
    temp = []
    ip_regex = regex_create(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
    line = 1

    # Read the user file, and create variable values depending on if a field
    # is filled in
    with open(file_in, 'r') as input_file:
        params = reader(input_file)
        for row in params:
            default_name = None
            # Create a 5 element array if the user did not provide a file with
            # enough rows
            if len(row) != 5:
                for i in range(0, (5 - len(row))):
                    row.append('')

            # Exit if there are too many rows in proivded .csv
            if len(row) > 5:
                print("error: please specify a .csv with 5 or less fields")
                raise SystemExit

            # Address object generation specific code
            if mode == 'ip':
                if row[1] is not '' and ip_regex.search(row[1]):
                    ip_addr = '%s/%s' % (row[0], row[1])
                    if row[3] is not '':
                        default_name = IPv4Network(ip_addr)
                else:
                    ip_addr = row[0]
                    if row[3] is not '':
                        default_name = IPv4Network(ip_addr)

                # Check to see if the user provides an interface,
                # and make sure they also provide the necessary interface
                # parameters
                if row[2] is not '':
                    interface = row[2]
                else:
                    interface = None

            # Service object generation specific code
            if mode == 'port':
                protocol = protocol_check(row[0], row[1] + row[2])
                line += 1
                dst_port = port_check(row[1])
                if row[2] is not '':
                    src_port = port_check(row[2])
                else:
                    src_port = None
                if row[3] is '':
                    default_name = protocol + "_" + dst_port

            # General object generation code
            # Check to see if the user provides a custom name
            if default_name is not None:
                name = default_name
            else:
                name = row[3]

            # Check to see if the user provides a comment
            if row[4] is not '':
                comment = row[4]
            else:
                comment = None

            # Append the correct values based on if we are generating an
            # address or a service
            if mode == 'ip':
                temp = [ip_addr, name, interface, comment]
            elif mode == 'port':
                temp = [protocol, dst_port, src_port, name, comment]
            array.append(temp)

    # If the user did not provide a vdom, generate a timestamp to use as a
    # default name instead
    edit_vdom = True
    if vdom is False:
        vdom = strftime("%d-%m-%Y%_H:%M:%S")
        edit_vdom = False

    # Create a .txt file using the users parameters
    if mode == 'ip':
        with open(vdom + '.txt', 'w') as output_file:
            if edit_vdom is False:
                header(vdom, output_file, mode, edit_vdom)
            else:
                header(vdom, output_file, mode)
            for row in array:
                ip_addr = ip_check(row[0])
                if ip_addr[1] == 'ip' and row[1] is None:
                    name = ip_addr[0].with_prefixlen
                elif array[1] is None:
                    name = ip_addr[0]
                else:
                    name = row[1]

                # Generate Entry
                generate_name(name, output_file)
                if row[2] is not None:
                    generate_interface(row[2], output_file)
                if ip_addr[1] == 'ip':
                    generate_ip(ip_addr[0], output_file)
                else:
                    generate_url(ip_addr[0], output_file)
                generate_end(output_file)

    elif mode == 'port':
        with open(vdom + '.txt', 'w') as output_file:
            header(vdom, output_file, mode)
            for row in array:
                generate_name(row[3], output_file, True)
                if row[0] == 'both':
                    generate_service(output_file, 'tcp', row[1], row[2])
                    generate_service(output_file, 'udp', row[1], row[2])
                else:
                    generate_service(output_file, row[0], row[1], row[2])
                if row[4] is not None:
                    generate_comment(row[4], output_file)
                generate_end(output_file)

    # Print the users created file
    with open(vdom + '.txt', 'r') as finished_file:
        print("")
        print(finished_file.read())

# ------------------------------------------------------------------------------
#                               Input Validation
# ------------------------------------------------------------------------------


def ip_check(ip_addr):
    """
    Checks if a given entry is an IP address or URL.
    Returns an IP if an object can be created using ipaddress.IPv4Network.
    If the string appears to look like an IP, but is formatted wrong,
    the user is prompted
    Otherwise returns a string, which should be a url

    ip_addr -- String to be tested.
    """

    y_or_n = "n"
    ip_regex = regex_create(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

    try:
        # Create an IP object if possible
        ip_addr = IPv4Network(ip_addr)
        return (ip_addr, 'ip')
    except ValueError:
        # If the user provides a string that looks like an IP,
        # ask if it is, and if they respond yes, prompt for the IP again.
        if ip_regex.search(ip_addr) is not None:
            y_or_n = input(
                "Is " + ip_addr + " supposed to be an ip address? y | [n]: ") or "n"
        if y_or_n == "y":
            ip_addr = input(
                "Please specify an IP/CIDR network address: ")
            ip_check(ip_addr)
        # Return a URL
        else:
            return (ip_addr, 'url')


def port_check(port):
    port_range_regex = regex_create(
        r"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$")
    if port.isdigit() is True:
        test = int(port)
        if test > 0 and test <= 65535:
            return port
        else:
            port = input(
                "%s is invalid.  Please input a valid port from 1-65535, or range using " % (port))
            port = port_check(port)
            return port

    elif port_range_regex.search(port):
        return port
    else:
        port = input(
            "%s is invalid.  Please input a valid port from 1-65535, or range using " % (port))
        port = port_check(port)
        return port


def protocol_check(protocol, line):
    tcp_regex = regex_create(r"tcp")
    udp_regex = regex_create(r"udp")
    tcp_udp_regex = regex_create(r"both")
    if tcp_regex.search(protocol) or udp_regex.search(protocol) or tcp_udp_regex.search(protocol):
        return protocol
    else:
        protocol = input(
            "%s is an invalid protocol. Please enter a valid protocol for line %s" % (protocol, line))
        protocol = protocol_check(protocol, line)
        return protocol

# ------------------------------------------------------------------------------
#                           Text Generation Methods
# ------------------------------------------------------------------------------


def header(vdom, output_file, mode, edit_vdom=True):
    """
    Generates the first 3 lines to paste into a fortigate.

    vdom -- The user provided vdom
    output_file -- The file to be written to
    mode -- set address or service object ('ip', 'port')
    edit_vdom -- Optional argument for if no VDOM was specified by the user.
    """
    if edit_vdom is True:
        output_file.write("config vdom\n")
        output_file.write("edit %s\n" % str(vdom))
    if mode == 'ip':
        output_file.write("config firewall address\n\n")
    elif mode == 'port':
        output_file.write("config firewall service custom\n\n")


def generate_name(name, output_file, service=False):
    """
    Generates the name line for an address object

    name -- A name, either user provided or automatically generated
    output_file -- The file to be written to
    service -- Optional boolean for custom services, defaults to not set a protocol
    """

    output_file.write("edit \"%s\"\n" % name)
    if service is True:
        output_file.write("set protocol TCP/UDP/SCTP\n")


def generate_interface(interface, output_file):
    """
    Generates the interface line for an address object.

    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write("set associated-interface \"%s\"\n" % (interface))


def generate_comment(comment, output_file):
    """
    Generates the interface line for an address object.

    ip_addr -- IP address network object
    output_file -- An output text file
    """
    output_file.write("set comment \"%s\"\n" % (comment))


def generate_ip(ip_addr, output_file):
    """
    Generate a single IP address object.

    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write("set subnet %s %s\n" %
                      (str(ip_addr.network_address), str(ip_addr.netmask)))


def generate_url(url, output_file):
    """
    Generate a single URL address object.

    url -- A valid URL string
    output_file -- An output text file
    """

    output_file.write("set type fqdn\n")
    output_file.write("set fqdn %s\n" % url)


def generate_service(output_file, protocol, dst_port, src_port=None):
    """
    Generate a single custom service object

    output_file -- An output text file
    protocol -- Accepts 'tcp' or 'udp' to determine the necessary protocol.  Call twice for both.
    dst_port -- Destination port(s)
    src_port -- Source port(s) (Optional)
    """

    if src_port is None and protocol == 'tcp' or protocol == 'udp':
        output_file.write("set %s-portrange %s\n" % (protocol, dst_port))
    else:
        output_file.write("set %s-portrange %s:%s\n" %
                          (protocol, dst_port, src_port))


def generate_end(output_file):
    """
    Generate the next statement

    output_file -- An output text File
    """
    output_file.write("next\n\n")

if __name__ == '__main__':
    Main()

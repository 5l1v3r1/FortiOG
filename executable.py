#!/bin/python3
#
#   +-------------------------------------------------------------------------+
#   |              *** Distribution under the GPLv3 License ***               |
#   |-------------------------------------------------------------------------|                                                                     |
#   |  This program is free software: you can redistribute it and/or modify   |
#   |  it under the terms of the GNU General Public License as published by   |
#   |  the Free Software Foundation, either version 3 of the License, or      |
#   |  (at your option) any later version.                                    |
#   |                                                                         |
#   |  This program is distributed in the hope that it will be useful,        |
#   |  but WITHOUT ANY WARRANTY; without even the implied warranty of         |
#   |  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          |
#   |  GNU General Public License for more details.                           |
#   |                                                                         |
#   |  You should have received a copy of the GNU General Public License      |
#   |  along with this program.  If not, see <http://www.gnu.org/licenses/>.  |
#   +-------------------------------------------------------------------------+
#
#   For questions, comments, and suggestions please reach out to the authors at:
#   brandonforces@gmail.com or bryce.zuccaro@gmail.com


from argparse import ArgumentParser, RawTextHelpFormatter
from csv import DictReader
from ipaddress import IPv4Network
from os import getcwd, path, sep
from re import compile as regex_create
from time import strftime
from tkinter.filedialog import Tk, askopenfilename



def main():
    """ Main Program """

    # Parser for user CLI interaction
    parser = ArgumentParser(
        description='Provided a list of IP addresses or URL\'s, format the proper Fortigate '
                    'commands to create them and output to a file within the current working directory.\n'
                    'DISCLAIMER: If you run something on a firewall that you shouldn\'t have, '
                    'we are NOT responsible. READ YOUR CODE BEFORE YOU PLACE IT!!!',
        usage='VDOM input_file.txt or .csv',
        formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        '-v', '--VDOM', help='Specify the VDOM to which changes will be applied.\n\n', default=False)
    parser.add_argument(
        '-f', '--File', help='Accepts two kinds of files, .txt & .csv. If no file is given, '
        'the file explorer will launch and you will be prompted to select one.\n'
        'Each type should be formatted differently.\n'
        '.txt: Each entry should be on its own line, formatted as IP/CIDR, IP/Netmask or a URL.\n'
        '.csv: Should consist of 5 fields.  The first is required, the rest are optional:\n\n'
        'IP/CIDR or URL (the CIDR prefix is optional, and just an IP can be accepted)\n'
        'Netmask (needed if you do not provide a CIDR in the previous field)\n'
        'Custom Name for the object\n'
        'Interface to associate object to\n'
        'Comment to label the object\n\n'
        '.csv\'s should be formatted similarly to an Excel .csv')
    address_or_service = parser.add_mutually_exclusive_group()
    address_or_service.add_argument('-a', '--address', default=True, action='store_true',
                                    help='Create address objects.')
    address_or_service.add_argument('-s', '--service', default=False, action='store_true',
                                    help='Create service objects.')
    args = parser.parse_args()

    # If args.File is given, proceed to launch function. Else, launch file
    # explorer and then proceed.
    if args.File:
        launch(args.VDOM, args.File, args.address, args.service)
    else:
        root = Tk()
        root.withdraw()  # Prevents empty root window from displaying.
        launch(args.VDOM, askopenfilename(), args.address, args.service)


def launch(vdom, input_file, address, service):
    """
    Given a .txt or .csv file, txt or csv mode is called respectively.
    Else, the appropriate error is thrown.
    vdom -- args.VDOM
    file -- Input file. Specified via file explorer or args.File.
    """

    if not input_file:
        print(FileNotFoundError('\nNo file selected. Please try again.\n\n'))
        pass
    elif input_file.endswith('.txt') and address is True:
        txt_mode(vdom, input_file, 'address')
    elif input_file.endswith('.txt') and service is True:
        txt_mode(vdom, input_file, 'service')
    elif input_file.endswith('.csv') and address is True:
        csv_mode(vdom, input_file, 'address')
    elif input_file.endswith('.csv') and service is True:
        csv_mode(vdom, input_file, 'service')
    else:
        print(ValueError('\nPlease select a valid file type. (.txt, .csv)\n\n'))


# ------------------------------------------------------------------------------
#                           .txt File Methods
# ------------------------------------------------------------------------------


def txt_mode(vdom, file_in, mode):
    """
    Function created to handle simple text files
    vdom -- the user input vdom
    file_in -- the user input file
    mode -- Accepts 'address' or 'service' for address or service objects
    """

    line = 1

    # Read in users list of parameters
    with open(file_in, 'r') as input_file:
        array = input_file.read().splitlines()

    output_file, vdom = generate_file(mode, vdom)

    # Address Groups
    if mode == 'address':
        for element in array:
            address, mode = ip_check(element, line)

            if mode == 'ip':
                name = address.with_prefixlen
                generate_name(output_file, name)
                generate_ip(output_file, address)
                generate_end(output_file)

            elif mode == 'url':
                name = address
                generate_name(output_file, name)
                generate_url(output_file, address)
                generate_end(output_file)

            line += 1

    # Service Groups
    elif mode == 'service':
        for element in array:
            service = port_check(element, line)
            generate_name(output_file, 'tcp_udp_' + service, True)
            generate_service(output_file, 'tcp', service)
            generate_service(output_file, 'udp', service)
            generate_end(output_file)
            line += 1

    output_file.close()

    print_finished_objects(vdom)


# ------------------------------------------------------------------------------
#                           .csv File Functions
# ------------------------------------------------------------------------------


def csv_mode(vdom, file_in, mode):
    """
    Handles csv files
    csv files should have 4 fields, the last 3 are optional:
    IP, netmask, name, interface
    vdom -- the user input vdom
    file_in -- the user input file
    mode -- Accepts 'ip' or 'port' for address or service objects
    """

    line = 1
    dictionary = create_dictionary(file_in, mode)
    output_file, vdom = generate_file(mode, vdom)

    # Address Objects
    if mode == 'address':
        for row in dictionary:
            create_address(output_file, row, line)
            line += 1
    # Service Objects
    elif mode == 'service':
        for row in dictionary:
            create_service(output_file, row, line)
            line += 1

    output_file.close()

    print_finished_objects(vdom)


def create_dictionary(file_in, mode):
    """
    Generates a dictionary with keys based on the mode
    file_in -- User input file
    mode -- 'address' or 'service'
    Returns a dictionary
    """

    fields = []
    dictionary = []
    # Address object .csv fields.  Only Address is required
    if mode == 'address':
        fields = ['address', 'netmask', 'interface', 'name', 'comment']
    # Service object .csv fields.  Protocol & dst_port are required
    elif mode == 'service':
        fields = ['protocol', 'dst_port', 'src_port', 'name', 'comment']

    with open(file_in, 'r') as input_file:
        dict_reader = DictReader(input_file, fieldnames=fields, restval='')
        for row in dict_reader:
            dictionary.append(row)

    return dictionary


def create_address(output_file, dictionary, line):
    """
    Create a single address object.
    output_file -- An open file to be written to.
    dictionary -- A dictionary of parameters to be used.
    """

    address, mode = address_fixer(dictionary['address'], dictionary['netmask'], line)

    name = name_fixer(dictionary['name'], address)

    generate_name(output_file, name)

    if dictionary['interface'] is not '':
        generate_interface(output_file, dictionary['interface'])

    if mode == 'ip':
        generate_ip(output_file, address)
    elif mode == 'url':
        generate_url(output_file, address)

    if dictionary['comment'] is not '':
        generate_comment(output_file, dictionary['comment'])
    generate_end(output_file)


def create_service(output_file, dictionary, line):
    """
    Create a single service object.
    output_file -- An open file to be written to
    dictionary -- A dictionary of parameters to be used
    """

    protocol = protocol_check(dictionary['protocol'], line)
    dst_port = port_check(dictionary['dst_port'], line)
    name = name_fixer(dictionary['name'], protocol + '_' + dst_port)

    generate_name(output_file, name, True)

    if dictionary['src_port'] is '':
        generate_service(output_file, protocol, dst_port)
    else:
        src_port = port_check(dictionary['src_port'], line)
        generate_service(output_file, protocol, dst_port, src_port)

    if dictionary['comment'] is not '':
        generate_comment(output_file, dictionary['comment'])

    generate_end(output_file)


def address_fixer(address, netmask, line):
    """
    Combines an address with a netmask
    address -- An IP address
    netmask -- A netmask
    line -- Provides the user with information about which line
    of their file an error may be located on.

    Returns a tuple of (address (IPv4Network or str), type ('ip' or 'url'))
    """

    ip_regex = regex_create(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r'\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    if netmask is not '' and ip_regex.search(address):
        address = ip_check('%s/%s' % (address, netmask), line)
        # If the user did not provide a name, create a default one from network object
    elif netmask is '':
        address = ip_check(address, line)

    return address[0], address[1]


def name_fixer(name, default_name):
    """
    Checks to see if the user provided a name.
    If not, set name to the provided default.
    name -- User provided name value
    default_name -- User provided value, should be an IP, URL, or service
    Returns a name as a string
    """

    if name is not '':
        return name
    else:
        name = default_name
        return name


# ------------------------------------------------------------------------------
#                             Checks & Validation
# ------------------------------------------------------------------------------

def ip_check(ip_addr, line):
    """
    Checks if a given entry is an IP address or URL.
    Returns an IP if an object can be created using ipaddress.IPv4Network.
    If the string appears to look like an IP, but is formatted wrong,
    the user is prompted.
    ip_addr -- String to be tested.
    Returns (IP/URL, 'ip'/'url')
    """

    y_or_n = 'n'
    ip_regex = regex_create(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    try:
        # Create an IP address object if possible
        ip_addr = IPv4Network(ip_addr)
        return ip_addr, 'ip'
    except ValueError:
        # If the user provides a string that looks like an IP,
        # ask if it is, and if they respond yes, prompt for the IP again.
        if ip_regex.search(ip_addr) is not None:
            y_or_n = input(
                'Is %s on line %s supposed to be an ip address? y | [n]: '
                % (ip_addr, line)) or 'n'
        if y_or_n == 'y':
            ip_addr = input('Please specify a network address using CIDR notation: ')
            # Mode is here to ensure that we return nothing as a tuple.
            ip_addr, mode = ip_check(ip_addr, line)
            return ip_addr, 'ip'
        # Return a URL
        else:
            return ip_addr, 'url'


def port_check(port, line):
    """
    Checks if a provided string is a valid port between 1-65535,
    or range with end points between 1-65535.
    port -- Integer to be tested.
    line -- A count of how many lines in a file the user has been through
    Returns a valid port as a string.
    """

    # Regex checking for a port range, Ex. 123-456
    port_range_regex = regex_create(
        r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]'
        r'{2}|655[0-2][0-9]|6553[0-5])(-[1-9][0-9]{0,3}|[1-5][0-9]{4}'
        r'|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$')

    # If a provided string is a digit, check its a valid port, or prompt the user for one.
    if port.isdigit() is True:
        test = int(port)
        if 0 < test <= 65535:
            return port
        else:
            port = input('%s is invalid.  \
            Please input a valid port from 1-65535, or range using a -:  ' % port)
            port = port_check(port, line)
            return port

    # Check a string against the port range regex, prompt user on invalid port
    elif port_range_regex.search(port):
        return port
    else:
        port = input(
            '%s is invalid.  Please input a valid port from 1-65535, or range using a -: '
            % port)
        port = port_check(port, line)
        return port


def protocol_check(protocol, line):
    """
    Provided a user string, ensure it is a valid protocol
    protocol -- Checks for 'tcp', 'udp', 'both' (tcp & udp)
    line -- A count of how many lines in a file the user has been through
    Returns protocol
    """

    if protocol == 'tcp' or protocol == 'udp' or protocol == 'both':
        return protocol
    else:
        protocol = input(
            '%s is an invalid protocol. Please enter a valid protocol for line %s: '
            % protocol, line)
        protocol = protocol_check(protocol, line)
        return protocol


# ------------------------------------------------------------------------------
#                           Text Generation
# ------------------------------------------------------------------------------

def create_file_name(vdom):
    """
    Checks if the current working directory contains a file with the same name
    as the output file. If so, alter output file name
    """

    # If the user did not provide a name, generate a timestamp to use as one instead
    if vdom is False:
        vdom = strftime('FortiOG %b-%d-%y')

    # Increment the file name by one if file name exists in current directory
    sequence_int = 0
    sequence_str = ''
    file_name = (vdom + '%s' + '.txt')
    while path.isfile(file_name % sequence_str):
        if sequence_int < 20:
            sequence_int += 1
            sequence_str = ' (%s)' % str(sequence_int)
        else:
            sequence_str = ''
            sequence_int = 0

    file_name %= sequence_str

    return file_name


def generate_file(mode, vdom=False):
    """
    Creates a new .txt file for the users objects
    Generates a name based on a time stamp if no vdom is provided
    mode -- set address or service object ('address' | 'service')
    vdom -- user provided value
    Returns an open file
    """

    # Determine whether or not edit 'vdom' is needed in header.
    edit_vdom = True
    if vdom is False:
        edit_vdom = False

    # Determines which file name to use; vdom or default (strftime), and creates file name.
    vdom = create_file_name(vdom)

    # Create a new output file using the users parameters
    output_file = open(vdom, 'w')

    # Generate header of output file, dependent upon whether 'edit vdom' is required.
    if edit_vdom is False:
        generate_header(vdom, output_file, mode, edit_vdom)
    else:
        generate_header(vdom, output_file, mode)

    return output_file, vdom


def generate_header(vdom, output_file, mode, edit_vdom=True):
    """
    Generates the first 3 lines to paste into a Fortigate.
    vdom -- The user provided vdom
    output_file -- The file to be written to
    mode -- set address or service object ('address', 'port')
    edit_vdom -- Optional argument for if no VDOM was specified by the user.
    """

    # Strips the file ending off of 'vdom' if a vdom was given.
    strip_file_name = regex_create(r'\s\(\d+\)(.txt)')
    if strip_file_name.search(vdom):
        vdom = vdom[:-8]
    else:
        vdom = vdom[:-4]

    if edit_vdom:
        output_file.write('config vdom\n')
        output_file.write('edit %s\n' % str(vdom))

    if mode == 'address':
        output_file.write('config firewall address\n')
    elif mode == 'service':
        output_file.write('config firewall service custom\n')


def generate_name(output_file, name, service=False):
    """
    Generates the name line for an address object
    name -- A name, either user provided or automatically generated
    output_file -- The file to be written to
    service -- Set to True for custom service objects, (Optional)
    """

    output_file.write('edit \'%s\'\n' % name)

    if service is True:
        output_file.write('set protocol TCP/UDP/SCTP\n')


def generate_interface(output_file, interface):
    """
    Generates the interface line for an address object.
    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write('set associated-interface \'%s\'\n' % interface)


def generate_comment(output_file, comment):
    """
    Generates the interface line for an address object.
    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write('set comment \'%s\'\n' % comment)


def generate_ip(output_file, ip_addr):
    """
    Generate a single IP address object.
    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write('set subnet %s %s\n' %
                      (str(ip_addr.network_address), str(ip_addr.netmask)))


def generate_url(output_file, url):
    """
    Generate a single URL address object.
    url -- A valid URL string
    output_file -- An output text file
    """

    output_file.write('set type fqdn\n')
    output_file.write('set fqdn %s\n' % url)


def generate_service(output_file, protocol, dst_port, src_port=None):
    """
    Generate a single custom service object
    output_file -- An output text file
    protocol -- Accepts 'tcp' or 'udp' to determine the necessary protocol.  Call twice for both.
    dst_port -- Destination port(s)
    src_port -- Source port(s) (Optional)
    """

    if src_port is None and (protocol == 'tcp' or protocol == 'udp'):
        output_file.write('set %s-portrange %s\n' % (protocol, dst_port))
    else:
        output_file.write('set %s-portrange %s:%s\n' %
                          (protocol, dst_port, src_port))


def generate_end(output_file):
    """
    Generate the next statement
    output_file -- An output text File
    """

    output_file.write('next\n\n')


def print_finished_objects(vdom):
    """
    Prints the finished objects to screen and output file.
    """

    with open(vdom, 'r') as finished_file:
        print('\n\n', finished_file.read().strip(), '\nend\n\n', sep='')
    print('This has been saved as a text file to >> %s%s%s' % (getcwd(), sep, vdom))


if __name__ == '__main__':
    main()

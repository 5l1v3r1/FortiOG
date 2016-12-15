#!/bin/python3
from argparse import ArgumentParser, RawTextHelpFormatter
from csv import reader
from ipaddress import IPv4Network
from os import getcwd
from re import compile as regex_create
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
        'VDOM', help='Specify the VDOM to which changes will be applied.\n\n')
    parser.add_argument(
        '--File', help='Accepts two kinds of files, .txt & .csv. '
                       'Each type should be formatted differently.\n'
                       '.txt: Each entry should be on its own line, formatted as IP/CIDR, IP/Netmask or a URL.\n'
                       '.csv: Should consist of 5 fields.  The first is required, the rest are optional:\n\n'
                       'IP/CIDR or URL (the CIDR prefix is optional, and just an IP can be accepted)\n'
                       'Netmask (needed if you do not provide a CIDR in the previous field)\n'
                       'Custom Name for the object\n'
                       'Interface to associate object to\n'
                       'Comment to label the object\n\n'
                       '.csv\'s should be formatted similarly to an Excel .csv')
    args = parser.parse_args()

    # If args.File is given, proceed to launch function. Else, launch file explorer and then proceed.
    if args.File:
        launch(args.VDOM, args.File)
    else:
        root = Tk()
        root.withdraw()  # Prevents empty root window from displaying.
        launch(args.VDOM, askopenfilename())


def launch(vdom, file):
    """
    Given a .txt or .csv file, txt or csv mode is called respectively.
    Else, the appropriate error is thrown.

    vdom -- args.VDOM
    file -- Input file. Specified via file explorer or args.File.
    """
    if not file:
        print(FileNotFoundError('No file selected. Please try again.'))
    elif file.endswith('.txt'):
        txt_mode(vdom, file)
    elif file.endswith('.csv'):
        csv_mode(vdom, file)
    else:
        print(ValueError('Please select a valid file type. (.txt, .csv)'))


def txt_mode(vdom, file_in):
    """
    Function created to handle simple text files

    vdom -- the user input vdom
    file_in -- the user input file
    """
    # Read in users list of parameters
    with open(file_in, 'r') as input_file:
        array = input_file.read().splitlines()

    # Create a new file using the users parameters
    with open(vdom + '.txt', 'w') as output_file:
        header(vdom, output_file)
        for element in array:
            ip_addr = ip_check(element)

            # Create a name for an ip address, or use the users url string
            if ip_addr[1] == 'ip':
                name = ip_addr[0].with_prefixlen
            else:
                name = ip_addr[0]

            # Generate entry
            generate_name(name, output_file)
            if ip_addr[1] == 'ip':
                generate_ip(ip_addr[0], output_file)
            else:
                generate_url(ip_addr[0], output_file)

    # print the users created file
    with open(vdom + '.txt', 'r') as finished_file:
        print(finished_file.read())
        print('Your file has been saved to ', getcwd())


def csv_mode(vdom, file_in):
    """
    Function created to handle csv files
    csv files should have 4 fields, the last 3 are optional:
    IP, netmask, name, interface

    vdom -- the user input vdom
    file_in -- the user input file
    """
    array = []
    ip_regex = regex_create(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        r"\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

    # Read the user file, and create variable values depending on if a field is filled in
    with open(file_in, 'r') as input_file:
        params = reader(input_file)
        for row in params:
            ip_name = None
            # Create a 5 element array if the user did not provide a file with enough rows
            if len(row) != 5:
                for i in range(0, (5 - len(row))):
                    row.append('')

            # Exit if there are too many rows in proivded .csv
            if len(row) > 5:
                print("error: please specify a .csv with 5 or less fields")
                raise SystemExit

            # Check to see if the user provides a subnet mask in cell column 2
            if row[1] is not '' and ip_regex.search(row[1]) is not None:
                ip_addr = '%s/%s' % (row[0], row[1])
                ip_name = IPv4Network(ip_addr)
            else:
                ip_addr = row[0]
            # Check to see if the user provides a custom name
            if row[2] is not '':
                name = row[2]
            elif ip_name is not None:
                name = ip_name
            else:
                name = row[0]
            # Check to see if the user provides an interface,
            # and make sure they also provide the necessary interface parameters
            if row[3] is not '':
                interface = row[3]
            else:
                interface = None
            # Check to see if the user provides a comment
            if row[4] is not '':
                comment = row[4]
            else:
                comment = None

            temp = [ip_addr, name, interface, comment]
            array.append(temp)

    # Create a .txt file using the users parameters
    with open(vdom + '.txt', 'w') as output_file:
        header(vdom, output_file)
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

    # Print the users created file
    with open(vdom + '.txt', 'r') as finished_file:
        print(finished_file.read())
        print('Your file has been saved to ', getcwd())


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
        return ip_addr, 'ip'
    except ValueError:
        # If the user provides a string that looks like an IP,
        # ask if it is, and if they respond yes, prompt for the IP again.
        if ip_regex.search(ip_addr) is not None:
            y_or_n = input(
                "Is " + ip_addr + " supposed to be an ip address? y | [n]: ") or "n"
        if y_or_n == "y":
            ip_addr = input(
                "Please specify an IP/CIDR network address: ")
            ip_addr = ip_check(ip_addr)
            return ip_addr
        # Return a URL
        else:
            return ip_addr, 'url'


# ------------------------------------------------------------------------------
#                      Text Generation Methods
# ------------------------------------------------------------------------------


def header(vdom, output_file):
    """
    Generates the first 3 lines to paste into a fortigate.

    vdom -- The user provided vdom
    output_file -- The file to be written to
    """

    output_file.write("config vdom\n")
    output_file.write("edit %s\n" % str(vdom))
    output_file.write("config firewall address\n")


def generate_name(name, output_file):
    """
    Generates the name line for an address object

    name -- A name, either user provided or automatically generated
    output_file -- The file to be written to
    """

    output_file.write("edit \"%s\"\n" % name)


def generate_interface(interface, output_file):
    """
    Generates the interface line for an address object.

    ip_addr -- IP address network object
    output_file -- an output text file
    """

    output_file.write("set associated-interface \"%s\"\n" % interface)


def generate_comment(comment, output_file):
    """
    Generates the interface line for an address object.

    ip_addr -- IP address network object
    output_file -- an output text file
    """
    output_file.write("set comment \"%s\"\n" % comment)


def generate_ip(ip_addr, output_file):
    """
    Generate a single IP address object.

    ip_addr -- IP address network object
    output_file -- An output text file
    """

    output_file.write("set subnet %s %s\n" %
                      (str(ip_addr.network_address), str(ip_addr.netmask)))
    output_file.write("next\n\n")


def generate_url(url, output_file):
    """
    Generate a single URL address object.

    url -- A valid URL string
    output_file -- An output text file
    """

    output_file.write("set type fqdn\n")
    output_file.write("set fqdn %s\n" % url)
    output_file.write("next\n\n")


if __name__ == '__main__':
    main()


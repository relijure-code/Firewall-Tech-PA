import re
from collections import defaultdict
import sys
import glob
from openpyxl import Workbook

# Define patterns for relevant configuration parameters
FQDN_PATTERN = re.compile(r'set fqdn \"(?P<fqdn>.*?)\"')
DSTADDR_PATTERN = re.compile(r'set dstaddr (?P<dstaddr>.*)')
SUBNET_PATTERN = re.compile(r'(\d+\.\d+\.\d+\.\d+/\d+)')
IPRANGE_PATTERN = re.compile(r'(\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+)')
MEMBER_PATTERN = re.compile(r'set member (?P<member>.*?)$', re.DOTALL)
NAME_PATTERN = re.compile(r'set name \"(?P<name>.*?)\"')
EDIT_PATTERN = re.compile(r'edit \"(?P<edit>.*?)\"')
POLICY_PATTERN = re.compile(r'edit (?P<policy_id>\d+)')
SRCADDR_PATTERN = re.compile(r'set srcaddr (?P<srcaddr>.*?)$', re.DOTALL)

# Filter for specific configuration sections
VALID_SECTIONS = [
    "config firewall address",
    "config firewall addrgrp",
    "config firewall wildcard-fqdn group",
    "config webfilter urlfilter",
    "config dnsfilter domain-filter",
    "config webfilter ftgd-local-rating",
    "config firewall policy"
]

# Automatically find the first .conf file in the directory
config_files = glob.glob("*.conf")
if not config_files:
    raise FileNotFoundError("No .conf files found in the current directory.")
config_file = config_files[0]

try:
    print(f"Processing configuration file: {config_file}")

    # Dictionaries to store results
    fqdn_objects = defaultdict(list)
    dstaddr_objects = defaultdict(list)
    subnet_objects = defaultdict(list)
    iprange_objects = defaultdict(list)
    member_objects = defaultdict(list)
    group_memberships = defaultdict(list)
    policy_objects = defaultdict(list)
    name_objects = defaultdict(list)
    edit_objects = defaultdict(str)
    object_locations = defaultdict(lambda: defaultdict(list))

    # Helper function to update progress
    def update_progress(current, total, message):
        percent = (current / total) * 100
        sys.stdout.write(f"\r{message}... {percent:.2f}% complete")
        sys.stdout.flush()

    # Process the file line by line
    print("\nExtracting objects from configuration file...")
    total_lines = sum(1 for _ in open(config_file, "r"))
    inside_valid_section = None
    current_name = None
    current_edit = None
    current_policy = None

    with open(config_file, "r") as file:
        for i, line in enumerate(file, start=1):
            line = line.strip()

            # Check if we are inside a valid section
            for section in VALID_SECTIONS:
                if line.startswith(section):
                    inside_valid_section = section
                    break

            if line == "end":
                inside_valid_section = None
                current_name = None
                current_edit = None
                current_policy = None

            if inside_valid_section:
                # Match Edit (Group Name or Policy ID)
                if inside_valid_section == "config firewall addrgrp":
                    edit_match = EDIT_PATTERN.search(line)
                    if edit_match:
                        current_edit = edit_match.group("edit")

                if inside_valid_section == "config firewall policy":
                    policy_match = POLICY_PATTERN.search(line)
                    if policy_match:
                        current_policy = policy_match.group("policy_id")

                # Match Name
                name_match = NAME_PATTERN.search(line)
                if name_match:
                    current_name = name_match.group("name")
                    name_objects[current_name].append(f"Line {i}")
                    object_locations[current_name][inside_valid_section].append(f"Line {i}")

                # Match FQDN objects
                fqdn_match = FQDN_PATTERN.search(line)
                if fqdn_match:
                    fqdn = fqdn_match.group("fqdn")
                    fqdn_objects[fqdn].append(f"Line {i}")
                    object_locations[fqdn][inside_valid_section].append(f"Line {i}")

                # Match Destination Address objects
                dstaddr_match = DSTADDR_PATTERN.search(line)
                if dstaddr_match:
                    dstaddr = dstaddr_match.group("dstaddr").strip('"')
                    dstaddr_objects[dstaddr].append(f"Line {i}")
                    object_locations[dstaddr][inside_valid_section].append(f"Line {i}")

                # Match Subnet objects
                subnet_match = SUBNET_PATTERN.search(line)
                if subnet_match:
                    subnet = subnet_match.group(0)
                    subnet_objects[subnet].append(f"Line {i}")
                    object_locations[subnet][inside_valid_section].append(f"Line {i}")

                # Match IP Range objects
                iprange_match = IPRANGE_PATTERN.search(line)
                if iprange_match:
                    iprange = iprange_match.group(0)
                    iprange_objects[iprange].append(f"Line {i}")
                    object_locations[iprange][inside_valid_section].append(f"Line {i}")

                # Match Member objects
                member_match = MEMBER_PATTERN.search(line)
                if member_match:
                    members = member_match.group("member").split()
                    for member in members:
                        member = member.strip('"')
                        member_objects[member].append(f"Line {i}")
                        object_locations[member][inside_valid_section].append(f"Line {i}")
                        if current_edit:
                            edit_objects[member] = current_edit
                            group_memberships[member].append(current_edit)

                # Match Source Address objects in policies
                srcaddr_match = SRCADDR_PATTERN.search(line)
                if srcaddr_match:
                    srcaddrs = srcaddr_match.group("srcaddr").split()
                    for srcaddr in srcaddrs:
                        srcaddr = srcaddr.strip('"')
                        policy_objects[srcaddr].append(current_policy)
                        object_locations[srcaddr][inside_valid_section].append(f"Policy {current_policy}")

            # Update progress
            if i % 100 == 0 or i == total_lines:
                update_progress(i, total_lines, "Processing lines")

    print(f"\nProcessed {total_lines} lines.")

    # Generate Excel report
    print("\nGenerating Excel report...")
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Filtered Objects"

    # Add headers
    headers = ["Object Policy", "Grupo al que pertenece", "Policy ID", "Address Type", "Duplicado", "fqdn", "subnet", "iprange"]
    sheet.append(headers)

    # Add data rows
 # Add data rows
    processed_objects = set()  # Asegúrate de inicializar la variable aquí

    for name, locations in name_objects.items():
        groups = group_memberships.get(name, ["N/A"])
        policies = policy_objects.get(name, [])
        address_type = "fqdn" if name in fqdn_objects else "dstaddr" if name in dstaddr_objects else "subnet" if name in subnet_objects else "iprange" if name in iprange_objects else "unknown"
        duplicated = "si" if len(groups) > 1 or len(policies) > 1 else ""
        fqdn_value = name if address_type == "fqdn" else ""
        subnet_value = name if address_type == "subnet" else ""
        iprange_value = name if address_type == "iprange" else ""
        sheet.append([name, ", ".join(groups), ", ".join(policies), address_type, duplicated, fqdn_value, subnet_value, iprange_value])
        processed_objects.add(name)

    for dstaddr, locations in dstaddr_objects.items():
        if dstaddr not in processed_objects:
            groups = group_memberships.get(dstaddr, ["N/A"])
            policies = policy_objects.get(dstaddr, [])
            address_type = "dstaddr"
            duplicated = "si" if len(groups) > 1 or len(policies) > 1 else ""
            fqdn_value = ""
            subnet_value = dstaddr if address_type == "subnet" else ""
            iprange_value = dstaddr if address_type == "iprange" else ""
            sheet.append([dstaddr, ", ".join(groups), ", ".join(policies), address_type, duplicated, fqdn_value, subnet_value, iprange_value])
            processed_objects.add(dstaddr)

    for subnet, locations in subnet_objects.items():
        if subnet not in processed_objects:
            groups = group_memberships.get(subnet, ["N/A"])
            policies = policy_objects.get(subnet, [])
            address_type = "subnet"
            duplicated = "si" if len(groups) > 1 or len(policies) > 1 else ""
            fqdn_value = ""
            subnet_value = subnet
            iprange_value = ""
            sheet.append([subnet, ", ".join(groups), ", ".join(policies), address_type, duplicated, fqdn_value, subnet_value, iprange_value])
            processed_objects.add(subnet)

    for iprange, locations in iprange_objects.items():
        if iprange not in processed_objects:
            groups = group_memberships.get(iprange, ["N/A"])
            policies = policy_objects.get(iprange, [])
            address_type = "iprange"
            duplicated = "si" if len(groups) > 1 or len(policies) > 1 else ""
            fqdn_value = ""
            subnet_value = ""
            iprange_value = iprange
            sheet.append([iprange, ", ".join(groups), ", ".join(policies), address_type, duplicated, fqdn_value, subnet_value, iprange_value])
            processed_objects.add(iprange)

    # Save the Excel file
    excel_output = "filtered_objects_report.xlsx"
    workbook.save(excel_output)

    print(f"\nExcel report generated and saved to: {excel_output}")

except FileNotFoundError:
    print(f"Error: The file {config_file} was not found. Please ensure it exists and the path is correct.")
except Exception as e:
    print(f"An error occurred: {e}")

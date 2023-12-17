import boto3
import argparse


def check_security_groups(region):
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_security_groups()
    open_security_groups = {}
    for group in response['SecurityGroups']:
        sg_id = group['GroupId']
        sg_name = group.get('GroupName', 'No Name')
        for permission in group['IpPermissions']:
            for ip_range in permission['IpRanges']:
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if sg_id not in open_security_groups:
                        open_security_groups[sg_id] = {'name': sg_name, 'rules': []}
                    from_port = permission.get('FromPort', 'Any')
                    to_port = permission.get('ToPort', 'Any')
                    description = ip_range.get('Description', 'No Description')
                    port_range = f"{from_port}-{to_port}" if from_port != to_port else f"{from_port}"
                    open_security_groups[sg_id]['rules'].append((port_range, description))
    return open_security_groups


def format_output(security_groups):
    for sg_id, details in security_groups.items():
        print(f"SG-{sg_id} ({details['name']}):")
        for port, description in details['rules']:
            print(f"0.0.0.0/0 on port {port} ~ {description}")
        print()


def main(args):
    if args.region:
        region = args.region if args.region else input("Please enter a valid zone (example : 'us-east-2') :")
        client = boto3.client("ec2")
        zones = client.describe_availability_zones()
        zones_names = [zone['ZoneName'] for zone in zones['AvailabilityZones']]
        if region not in zones_names:
            print("Wrong Availability zone, please try again.")
            quit()
        else:
            open_sgs = check_security_groups(region)
            format_output(open_sgs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for a security group with the rule ANY:ANY opened.', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--region', '-r', type=str, help='Specify the region you want to search')
    ARGS = parser.parse_args()
    main(ARGS)


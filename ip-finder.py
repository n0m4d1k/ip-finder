import argparse
import os
import re

def initialize_files(log_file, output_file):
    """Delete old log and output files if they exist to ensure fresh output each run."""
    if os.path.exists(log_file):
        os.remove(log_file)
    if os.path.exists(output_file):
        os.remove(output_file)

def log_to_file(content, log_file):
    """Append content directly to the log file, as it would appear in a terminal."""
    with open(log_file, 'a') as f:
        f.write(content + "\n")

def run_command(command, log_file, debug=False):
    """Run a shell command and log its output, with debugging support."""
    if debug:
        print(f"Running command: {command}")
    else:
        print(f"Running command: {command}")
    
    result = os.popen(command).read()
    log_to_file(f"$ {command}", log_file)
    log_to_file(result, log_file)

    if debug:
        print(f"Command output:\n{result}")

    print("Completed command:", command)
    return result

def nslookup(endpoint, log_file, include_ipv6=False, debug=False):
    """Perform nslookup on the given endpoint and return associated IPs."""
    command = f'nslookup {endpoint}'
    result = run_command(command, log_file, debug=debug)

    # Refined patterns for IPv4 and IPv6
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}\b'
    combined_pattern = ipv4_pattern if not include_ipv6 else f"{ipv4_pattern}|{ipv6_pattern}"

    # Find and collect IPs from nslookup output
    ips = set()
    in_answer_section = False
    for line in result.splitlines():
        if debug:
            print(f"Processing line: {line}")  # Debugging each line
        if endpoint in line:  # Detect the answer section based on the endpoint name
            in_answer_section = True
        elif in_answer_section and "Address" in line:
            ip_matches = re.findall(combined_pattern, line)
            if debug:
                print(f"Matched IPs: {ip_matches}")  # Debug matched IPs
            ips.update(ip_matches)  # Add matched IPs directly to the set

    if debug:
        print(f"Final IPs for {endpoint}: {ips}")
    
    return endpoint, ips

def fetch_aws_ips(log_file, debug=False):
    """Fetch IPs from AWS describe-network-interfaces command."""
    required_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"]
    for var in required_vars:
        if not os.environ.get(var):
            raise EnvironmentError(f"Missing AWS environment variable: {var}. Please configure it and try again.")

    # Log the AWS Service Account Search section header before running the command
    log_to_file("\n==================== AWS Service Account Search ====================\n", log_file)

    command = (
        "aws ec2 describe-network-interfaces --output text --query 'NetworkInterfaces[].[Association.PublicIp,Ipv6Addresses]' | grep -v None"
    )
    result = run_command(command, log_file, debug=debug)
    
    # Extract IPs from result (both IPv4 and IPv6 addresses)
    ips = set(re.findall(r'(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+:+[a-fA-F0-9]+)', result))
    return ips

def write_ips_to_file(endpoint_ips, output_file, debug=False):
    """Write all endpoints and their IPs on a single line in the output file."""
    if debug:
        print(f"Writing all endpoints and IPs to {output_file} as a single line.")
    
    with open(output_file, 'w') as f:
        # Join each endpoint and its IPs in the format "endpoint ip1 ip2 ...", then join all entries with a space
        all_endpoints = " ".join(
            f"{endpoint} {' '.join(sorted(ips))}" for endpoint, ips in endpoint_ips.items() if ips
        )
        f.write(all_endpoints + "\n")
    
    print(f"All endpoints and IPs written to {output_file} as a single line.")

def main(args):
    # Check if AWS-only mode is active (only --aws without endpoints)
    aws_only_mode = args.aws and not args.endpoints

    # Prompt for AWS account number if in AWS-only mode
    account_number = ""
    if aws_only_mode:
        account_number = input("Enter AWS account number: ").strip()

    # Define output and log file names, with account number appended if in AWS-only mode
    output_file_name = f"ip-finder-output{f'-{account_number}' if aws_only_mode else ''}"
    log_file_name = f"ip-finder-log{f'-{account_number}' if aws_only_mode else ''}.txt"
    output_file = os.path.join(args.output, output_file_name)
    log_file = os.path.join(args.output, log_file_name)

    # Initialize (delete) log and output files at the start
    initialize_files(log_file, output_file)
    
    endpoint_ips = {}
    debug = args.debug

    if debug:
        print(f"Log file set to: {log_file}")
    
    # Perform nslookup if endpoints are provided
    if args.endpoints:
        try:
            with open(args.endpoints, 'r') as file:
                endpoints = [line.strip() for line in file if line.strip()]
            if debug:
                print(f"Endpoints loaded from {args.endpoints}: {endpoints}")
        except Exception as e:
            print(f"Error reading endpoints file: {e}")
            return

        print("Starting nslookup scans before VPN connection...")
        for endpoint in endpoints:
            endpoint_name, ips = nslookup(endpoint, log_file, include_ipv6=args.ipv6, debug=debug)
            endpoint_ips[endpoint_name] = ips
        print("Completed nslookup scans before VPN connection.")

        # VPN pause if specified
        if args.vpn:
            input("Connect to VPN and press any key to continue...")
            print("Connected to VPN. Starting nslookup scans on VPN...")
            log_to_file("\n==================== On VPN ====================\n", log_file)
            # Perform nslookup for each endpoint after VPN connection
            for endpoint in endpoints:
                endpoint_name, ips = nslookup(endpoint, log_file, include_ipv6=args.ipv6, debug=debug)
                endpoint_ips[endpoint_name].update(ips)
            print("Completed nslookup scans on VPN.")

    # Perform AWS IP search if --aws is specified
    if args.aws:
        if args.vpn and not args.endpoints:
            # Prompt for VPN if only AWS is being run
            input("Connect to VPN and press any key to continue...")
            print("Connected to VPN. Starting AWS IP search...")

        # Fetch AWS IPs
        try:
            print("Fetching IPs from AWS...")
            aws_ips = fetch_aws_ips(log_file, debug=debug)
            if aws_ips:  # Only add AWS results if there are IPs
                endpoint_ips["AWS"] = aws_ips
            print("Completed fetching IPs from AWS.")
        except EnvironmentError as e:
            print(e)
            return

    # Write deduped IPs to output file
    write_ips_to_file(endpoint_ips, output_file, debug=debug)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A script to perform nslookups and fetch AWS IPs.")
    
    parser.add_argument('-e', '--endpoints', required=False,
                        help="File containing list of endpoints for nslookup.")
    parser.add_argument('-o', '--output', required=True,
                        help="Directory to save the output file.")
    parser.add_argument('-v', '--vpn', action='store_true',
                        help="Wait for VPN connection before performing searches.")
    parser.add_argument('--aws', action='store_true',
                        help="Fetch IPs from AWS (requires VPN if --vpn is specified).")
    parser.add_argument('--ipv6', action='store_true',
                        help="Include IPv6 addresses in the output.")
    parser.add_argument('--debug', action='store_true',
                        help="Enable detailed debugging output.")
    
    args = parser.parse_args()
    
    # Ensure VPN requirement if AWS is selected
    if args.aws and not args.vpn:
        parser.error("--aws requires --vpn to be set")
    
    main(args)

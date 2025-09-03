import requests
import os
import logging
import argparse
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_auth_token(client_id, client_secret, base_url):
    """Get OAuth2 token from CrowdStrike"""
    auth_url = f"https://{base_url}/oauth2/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials'
    }
    
    try:
        logging.info(f"Attempting to get auth token from {auth_url}...")
        response = requests.post(auth_url, headers=headers, data=data)
        logging.info(f"Auth response status: {response.status_code}")
        
        if response.status_code == 201:
            token_data = response.json()
            return token_data.get('access_token')
        else:
            raise Exception(f"Authentication failed with status {response.status_code}: {response.text}")
    except Exception as e:
        raise Exception(f"Authentication error: {str(e)}")

def query_unmanaged_hosts(base_url, token, limit=1000, after=None, sort=None):
    """Query unmanaged and unsupported hosts using the Discover API with cursor-based pagination"""
    # Use the combined endpoint
    url = f"https://{base_url}/discover/combined/hosts/v1"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Set specific filter for unmanaged and unsupported hosts
    params = {
        'filter': "entity_type:['unmanaged','unsupported']",
        'limit': limit
    }
    
    if after:
        params['after'] = after
    if sort:
        params['sort'] = sort
    
    logging.info(f'Querying with settings: limit={limit}, after={after[:50] + "..." if after and len(after) > 50 else after}')
    
    try:
        logging.info("Querying unmanaged and unsupported hosts...")
        response = requests.get(url, headers=headers, params=params)
        response_json = response.json()
        
        logging.debug(f"Combined query response: {response_json}")
        
        if response.status_code == 200:
            return response_json
        else:
            raise Exception(f"Query failed with status {response.status_code}: {response.text}")
            
    except Exception as e:
        error_message = f"Error querying hosts: {str(e)}"
        logging.error(error_message)
        return {
            "status": "error",
            "message": error_message
        }

def query_all_hosts_paginated(base_url, token, limit=1000, sort=None):
    """Query all unmanaged and unsupported hosts using cursor-based pagination"""
    all_hosts = []
    after_token = None
    page_count = 0
    total_retrieved = 0
    total_available = None
    
    while True:
        page_count += 1
        logging.info(f"Fetching page {page_count}...")
        
        # Query current page
        result = query_unmanaged_hosts(base_url, token, limit, after_token, sort)
        
        if result.get("status") == "error":
            logging.error(f"Error on page {page_count}: {result.get('message')}")
            break
        
        # Extract pagination info
        meta = result.get('meta', {})
        pagination = meta.get('pagination', {})
        resources = result.get('resources', [])
        
        # Get total count on first page
        if total_available is None:
            total_available = pagination.get('total', 0)
            logging.info(f"Total records available: {total_available}")
        
        # Add current page results
        all_hosts.extend(resources)
        total_retrieved += len(resources)
        
        logging.info(f"Page {page_count}: Retrieved {len(resources)} records. Total so far: {total_retrieved}/{total_available}")
        
        # Check if there are more pages
        after_token = pagination.get('after')
        if not after_token:
            logging.info("No more pages available. Pagination complete.")
            break
        
        # Safety check to prevent infinite loops
        if page_count > 100:  # Reasonable upper limit
            logging.warning("Reached maximum page limit (100). Stopping pagination.")
            break
    
    logging.info(f"Pagination complete. Retrieved {total_retrieved} total records across {page_count} pages.")
    
    # Return in same format as original function
    return {
        'meta': {
            'pagination': {
                'total': total_available,
                'retrieved': total_retrieved
            }
        },
        'resources': all_hosts
    }

def format_timestamp(timestamp_str):
    """Convert ISO timestamp string to readable format"""
    try:
        # Parse ISO format timestamp
        dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%SZ')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'N/A'

def format_host_details(hosts_data):
    """Format the host details as CSV"""
    if not hosts_data or 'resources' not in hosts_data:
        return "No host data available"

    formatted_output = []
    
    # Create CSV header
    formatted_output.append(
        "Host ID,Hostname,First Seen,Last Seen,Entity Type,MAC Address,Local IP Addresses,Discovered By"
    )

    # Process each host
    for host in hosts_data.get('resources', []):
        # Extract host details
        host_id = host.get('id', 'N/A')
        hostname = host.get('hostname', '--')  # Use actual hostname if available, otherwise '--'
        entity_type = host.get('entity_type', 'N/A')
        
        # Handle timestamps
        first_seen = format_timestamp(host.get('first_seen_timestamp', ''))
        last_seen = format_timestamp(host.get('last_seen_timestamp', ''))
        
        # Handle MAC addresses and IPs
        mac_addresses = set()
        local_ips = set()
        network_interfaces = host.get('network_interfaces', [])
        
        if isinstance(network_interfaces, list):
            for interface in network_interfaces:
                if isinstance(interface, dict):
                    if interface.get('mac_address'):
                        mac_addresses.add(interface['mac_address'])
                    if interface.get('local_ip'):
                        local_ips.add(interface['local_ip'])
        
        # Format MAC addresses and IPs
        mac_addr_str = '|'.join(sorted(mac_addresses)) if mac_addresses else 'N/A'
        local_ips_str = '|'.join(sorted(local_ips)) if local_ips else 'N/A'
        
        # Get discoverer information
        discoverers = '|'.join(host.get('discoverer_hostnames', [])) if host.get('discoverer_hostnames') else 'N/A'
        
        # Create CSV line - escape commas in fields if needed
        csv_line = f"{host_id},{hostname},{first_seen},{last_seen},{entity_type},{mac_addr_str},{local_ips_str},{discoverers}"
        formatted_output.append(csv_line)

    return "\n".join(formatted_output)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Query CrowdStrike Discover API for unmanaged and unsupported hosts with pagination'
    )
    
    # Required arguments
    parser.add_argument('--client-id', required=True, 
                        help='CrowdStrike API client ID')
    parser.add_argument('--client-secret', required=True, 
                        help='CrowdStrike API client secret')
    
    # Optional arguments
    parser.add_argument('--base-url', default='api.crowdstrike.com',
                        help='CrowdStrike API base URL (default: api.crowdstrike.com)')
    parser.add_argument('--limit', type=int, default=1000,
                        help='Number of results per page (max: 1000, default: 1000)')
    parser.add_argument('--sort',
                        help='Sort field and direction (e.g., hostname|asc, last_seen_timestamp|desc)')
    parser.add_argument('--output-file', default='results.csv',
                        help='File to save the results (default: results.csv)')
    parser.add_argument('--log-level', default='INFO', 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set logging level (default: INFO)')
    parser.add_argument('--single-page', action='store_true',
                        help='Retrieve only a single page of results (for testing)')
    
    return parser.parse_args()

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Validate limit
    if args.limit > 1000:
        logging.warning("Limit cannot exceed 1000. Setting limit to 1000.")
        args.limit = 1000
    
    try:
        # Get authentication token
        token = get_auth_token(args.client_id, args.client_secret, args.base_url)
        logging.info("Successfully obtained auth token")
        
        # Query hosts - either single page or all pages
        if args.single_page:
            logging.info("Single page mode - retrieving only first page")
            hosts_result = query_unmanaged_hosts(
                base_url=args.base_url,
                token=token,
                limit=args.limit,
                sort=args.sort
            )
        else:
            logging.info("Paginated mode - retrieving all available records")
            hosts_result = query_all_hosts_paginated(
                base_url=args.base_url,
                token=token,
                limit=args.limit,
                sort=args.sort
            )

        # Check if we got results
        if hosts_result.get("status") == "error":
            logging.error(f"Query failed: {hosts_result.get('message')}")
            exit(1)
        
        # Log summary
        total_records = len(hosts_result.get('resources', []))
        meta = hosts_result.get('meta', {})
        pagination = meta.get('pagination', {})
        total_available = pagination.get('total', total_records)
        
        logging.info(f"Query complete. Retrieved {total_records} records out of {total_available} available.")
        
        # Format results
        output = format_host_details(hosts_result)
        
        # Save to CSV file
        output_file = args.output_file
        if not output_file.endswith('.csv'):
            output_file += '.csv'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        
        logging.info(f"Results saved to {output_file}")
        logging.info(f"CSV contains {total_records} host records")
        
        # Also print summary to console
        print(f"Successfully retrieved {total_records} host records and saved to {output_file}")

    except Exception as e:
        logging.error(f"Error in main execution: {e}")
        exit(1)

if __name__ == '__main__':
    main()

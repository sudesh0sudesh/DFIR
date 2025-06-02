import json
import os
import time
import requests
import argparse
import ipaddress
from math import radians, cos, sin, asin, sqrt
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd


def load_ip_cache(filename: str = 'ip_data.json') -> Dict[str, Any]:
    """Load IP information cache from JSON file."""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading IP cache: {str(e)}")
    return {}


def save_ip_cache(ip_cache: Dict[str, Any], filename: str = 'ip_data.json'):
    """Save IP information cache to JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(ip_cache, f, indent=2)
    except Exception as e:
        print(f"Error saving IP cache: {str(e)}")


def calculate_distance(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float
) -> float:
    """Calculate the great circle distance between two points on the earth."""
    try:
        lat1, lon1, lat2, lon2 = map(
            radians,
            [float(lat1), float(lon1), float(lat2), float(lon2)]
        )

        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        # Radius of earth in kilometers
        r = 6371
        return c * r
    except (ValueError, TypeError):
        return 0


def detect_impossible_travel(
    entries: List[Dict[str, Any]],
    speed_threshold: float = 1000
) -> List[Dict[str, Any]]:
    """Detect impossible travel patterns in session data."""
    suspicious_events = []

    # Sort entries by timestamp
    sorted_entries = sorted(
        entries,
        key=lambda x: datetime.fromisoformat(
            x['CreatedDateTime'].replace('Z', '+00:00')
        )
    )

    for i in range(len(sorted_entries) - 1):
        current = sorted_entries[i]
        next_entry = sorted_entries[i + 1]

        # Skip if missing location data
        if not all([
            current['Latitude'],
            current['Longitude'],
            next_entry['Latitude'],
            next_entry['Longitude']
        ]):
            continue

        # Calculate time difference in hours
        time1 = datetime.fromisoformat(
            current['CreatedDateTime'].replace('Z', '+00:00')
        )
        time2 = datetime.fromisoformat(
            next_entry['CreatedDateTime'].replace('Z', '+00:00')
        )
        time_diff = (time2 - time1).total_seconds() / 3600

        if time_diff <= 0:
            continue

        # Calculate distance
        distance = calculate_distance(
            current['Latitude'],
            current['Longitude'],
            next_entry['Latitude'],
            next_entry['Longitude']
        )

        # Calculate speed (km/h)
        speed = distance / time_diff if time_diff > 0 else float('inf')

        # If speed exceeds threshold, mark as suspicious
        if speed > speed_threshold:
            # Get IP info for assessment
            ip1_info = {
                'org': current.get('ISP', ''),
                'domain': current.get('Domain', ''),
                'vpn': current.get('VPN', False),
                'proxy': current.get('Proxy', False),
                'hosting': current.get('Hosting', False)
            }
            ip2_info = {
                'org': next_entry.get('ISP', ''),
                'domain': next_entry.get('Domain', ''),
                'vpn': next_entry.get('VPN', False),
                'proxy': next_entry.get('Proxy', False),
                'hosting': next_entry.get('Hosting', False)
            }
            
            likelihood = assess_travel_likelihood(ip1_info, ip2_info)
            
            suspicious_events.append({
                'SessionId': current.get('EffectiveSessionId', 'unknown'),  # Make optional
                'Time1': current['CreatedDateTime'],
                'Location1': f"{current['City']}, {current['Country']}",
                'Time2': next_entry['CreatedDateTime'],
                'Location2': f"{next_entry['City']}, {next_entry['Country']}",
                'Distance': round(distance, 2),
                'TimeDiff': round(time_diff, 2),
                'Speed': round(speed, 2),
                'IP1': current['ClientIPAddress'],
                'IP2': next_entry['ClientIPAddress'],
                'Likelihood': likelihood,
                'IP1_Info': current.get('ISP', ''),
                'IP2_Info': next_entry.get('ISP', '')
            })

    return suspicious_events


def save_impossible_travel_analysis(
    events: List[Dict[str, Any]],
    output_file: str
) -> str:
    """Save impossible travel analysis to CSV file."""
    try:
        if events:
            travel_df = pd.DataFrame(events)
            travel_output = output_file.replace(
                '.csv',
                '_impossible_travel.csv'
            )
            travel_df.to_csv(travel_output, index=False)
            print(f"\nImpossible travel analysis saved to: {travel_output}")
            return travel_output

        print("\nNo impossible travel events detected")
        return None

    except Exception as e:
        print(f"Error saving impossible travel analysis: {str(e)}")
        return None


def extract_fields_from_json(audit_data: str) -> Tuple[str, ...]:
    """Extract relevant fields from audit data JSON."""
    try:
        data = json.loads(audit_data)
        return (
            data.get('AADSessionId', ''),
            data.get('ClientIP', '') or data.get('ClientIPAddress', ''),
            data.get('SessionId', ''),
            data.get('Subject', ''),
            data.get('ObjectId', ''),
            data.get('SiteUrl', ''),
            data.get('SourceFileName', ''),
            data.get('AppId', ''),           # Add AppId
            data.get('ClientAppId', '')     # Add ClientAppId
        )
    except Exception:
        return ('', '', '', '', '', '', '', '', '',)


def get_effective_session_id(session_id: str, aad_session_id: str) -> str:
    """Get effective session ID from available IDs."""
    return session_id or aad_session_id or 'unknown_session'


def get_operation_group(operation: str) -> str:
    """Categorize operation into groups."""
    operation_groups = {
        'mailbox_rules': {
            'Disable-InboxRule',
            'Enable-InboxRule',
            'New-InboxRule', 
            'Remove-InboxRule',
            'Set-InboxRule',
            'New-TransportRule',
            'Set-TransportRule',
            'Remove-TransportRule',
        },
        'mailbox_activity': {
            'HardDelete',
            'SoftDelete',
            'SendAs',
            'SendOnBehalf',
            'Add-MailboxPermission',
            'UpdateFolderPermissions'
        },
        'file_operations': {
            'FileAccessed',
            'FileCopied',
            'FileDeleted',
            'FileMalwareDetected',
            'FileDownloaded',
            'FileAccessedExtended',
            'SearchQueryPerformed'
        },
        'App Authorisation': {
            'Consent to application.',
        }
    }

    for group, operations in operation_groups.items():
        if operation in operations:
            return group
    return 'other'


def analyze_session_risks(
    extracted_data: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Analyze session risks based on location diversity and impossible travel.
    """
    session_locations: Dict[str, Dict] = {}

    for entry in extracted_data:
        session_id = entry['EffectiveSessionId']
        if not session_id:
            continue

        location = (entry['City'], entry['Region'], entry['Country'])

        if session_id not in session_locations:
            session_locations[session_id] = {
                'locations': set(),
                'details': []
            }

        if all(location):  # Only add if we have complete location info
            session_locations[session_id]['locations'].add(location)
            # Include EffectiveSessionId in details
            session_locations[session_id]['details'].append({
                'CreatedDateTime': entry['CreatedDateTime'],
                'ClientIPAddress': entry['ClientIPAddress'],
                'EffectiveSessionId': session_id,  # Add this line
                'City': entry['City'],
                'Region': entry['Region'],
                'Country': entry['Country'],
                'Latitude': entry['Latitude'],
                'Longitude': entry['Longitude']
            })

    # Detect impossible travel
    impossible_travel_events = []
    for session_id, data in session_locations.items():
        if len(data['details']) > 1:
            travel_events = detect_impossible_travel(data['details'])
            for event in travel_events:
                event['SessionId'] = session_id  # Add session ID to each event
            impossible_travel_events.extend(travel_events)

    # Calculate risk scores
    session_risks = []
    for session_id, data in session_locations.items():
        num_locations = len(data['locations'])
        impossible_travels = sum(
            1 for e in impossible_travel_events
            if e['SessionId'] == session_id
        )

        # Base risk score on number of locations and impossible travel events
        # Weight impossible travel higher
        risk_score = num_locations + (impossible_travels * 2)

        session_risks.append({
            'SessionId': session_id,
            'RiskScore': risk_score,
            'UniqueLocations': num_locations,
            'ImpossibleTravelEvents': impossible_travels,
            'Locations': [
                f"{loc[0]}, {loc[1]}, {loc[2]}"
                for loc in data['locations']
            ],
            'Details': data['details']
        })

    return session_risks, impossible_travel_events


def save_risk_analysis(risks: list, output_file: str):
    """Save risk analysis to CSV"""
    try:
        risk_data = []
        for risk in risks:
            # Create detailed entries for each location
            for detail in risk['Details']:
                risk_data.append({
                    'SessionId': risk['SessionId'],
                    'RiskScore': risk['RiskScore'],
                    'UniqueLocations': risk['UniqueLocations'],
                    'AllLocations': '; '.join(risk['Locations']),
                    'Timestamp': detail['time'],
                    'IP': detail['ip'],
                    'City': detail['city'],
                    'Region': detail['region'],
                    'Country': detail['country']
                })

        # Create DataFrame and save to CSV
        if risk_data:
            risk_df = pd.DataFrame(risk_data)
            risk_output = output_file.replace('.csv', '_risks.csv')
            risk_df.to_csv(risk_output, index=False)
            print(f"\nRisk analysis saved to: {risk_output}")
            return risk_output
        else:
            print("\nNo risk data to save")
            return None

    except Exception as e:
        print(f"Error saving risk analysis: {str(e)}")
        return None


def save_session_data(
    extracted_data: List[Dict[str, Any]],
    sessions_dir: str
) -> Tuple[str, List[str]]:
    """Save session-specific data to CSV files."""
    session_files = []
    
    # Group data by session ID
    session_data = {}
    for entry in extracted_data:
        session_id = entry['EffectiveSessionId']
        if session_id not in session_data:
            session_data[session_id] = []
        session_data[session_id].append(entry)
    
    # Save each session's data to a CSV file
    for session_id, entries in session_data.items():
        safe_session_id = ''.join(
            c if c.isalnum() else '_'
            for c in session_id
        )
        session_output = os.path.join(
            sessions_dir,
            f'session_{safe_session_id}.csv'
        )
        pd.DataFrame(entries).to_csv(session_output, index=False)
        session_files.append(session_output)
    
    combined_output = os.path.join(
        os.path.dirname(sessions_dir),
        'analysis_results',
        'extracted_data.csv'
    )
    pd.DataFrame(extracted_data).to_csv(combined_output, index=False)
    
    return combined_output, session_files

def save_operation_groups(
    extracted_data: List[Dict[str, Any]],
    operations_dir: str
) -> List[str]:
    """Save operation group specific data to CSV files."""
    group_files = []
    
    # Group data by operation type
    group_data = {}
    for entry in extracted_data:
        operation = entry['Operation']
        group = get_operation_group(operation)
        
        if group not in group_data:
            group_data[group] = []
        group_data[group].append(entry)
    
    # Save each group to a CSV file
    for group, entries in group_data.items():
        group_output = os.path.join(
            operations_dir,
            f'{group}_operations.csv'
        )
        pd.DataFrame(entries).to_csv(group_output, index=False)
        group_files.append(group_output)
        print(f"- {os.path.basename(group_output)}: {len(entries)} entries")
    
    return group_files


def get_ip_info(ip: str, ip_cache: Dict[str, Any]) -> dict:
    """Get IP information from cache or API."""
    if ip in ip_cache:
        return ip_cache[ip]

    default_info = {
        'city': '',
        'region': '',
        'country': '',
        'latitude': '',
        'longitude': '',
        'timezone': '',
        'postal': '',
        'org': '',
        'domain': '',
        'vpn': False,
        'proxy': False,
        'hosting': False
    }

    try:
        url = 'https://ipinfo.io/{}/json'.format(ip)
        params = {'token': '678b5f49c0f4c5'}
        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()

            # Parse location coordinates
            if 'loc' in data:
                try:
                    lat, lon = map(float, data['loc'].split(','))
                except (ValueError, AttributeError):
                    lat, lon = '', ''
            else:
                lat, lon = '', ''

            ip_info = {
                'city': data.get('city', ''),
                'region': data.get('region', ''),
                'country': data.get('country', ''),
                'latitude': lat,
                'longitude': lon,
                'timezone': data.get('timezone', ''),
                'postal': data.get('postal', ''),
                'org': data.get('org', ''),
                'domain': data.get('domain', ''),
                'vpn': 'vpn' in data.get('org', '').lower(),
                'proxy': any(
                    word in data.get('org', '').lower()
                    for word in ['proxy', 'vpn']
                ),
                'hosting': any(
                    word in data.get('org', '').lower()
                    for word in ['hosting', 'cloud', 'server']
                )
            }

            # Cache the result
            ip_cache[ip] = ip_info
            return ip_info

        time.sleep(1)  # Rate limiting
        return default_info

    except Exception as e:
        print(f"Error fetching IP info for {ip}: {str(e)}")
        return default_info


def detect_login_impossible_travel(
    login_data: pd.DataFrame, 
    max_display: int = 5,
    speed_threshold: float = 1000
) -> List[Dict[str, Any]]:
    """Detect impossible travel patterns from login data."""
    suspicious_patterns = []
    
    # Filter for UserLoggedIn operations
    login_events = login_data[login_data['Operation'] == 'UserLoggedIn'].copy()
    
    if login_events.empty:
        print("\nNo login events found to analyze.")
        return []

    # Sort by user and timestamp
    login_events['parsed_datetime'] = pd.to_datetime(login_events['CreatedDateTime'])
    login_events.sort_values(['Subject', 'parsed_datetime'], inplace=True)
    
    # Group by user
    for user, events in login_events.groupby('Subject'):
        if len(events) < 2:
            continue
            
        # Compare consecutive logins
        events = events.reset_index(drop=True)
        for i in range(len(events) - 1):
            current = events.iloc[i]
            next_login = events.iloc[i + 1]
            
            # Skip if missing location data
            if not all([
                current['Latitude'], current['Longitude'],
                next_login['Latitude'], next_login['Longitude']
            ]):
                continue
                
            # Calculate time difference
            time_diff = (
                next_login['parsed_datetime'] - current['parsed_datetime']
            ).total_seconds() / 3600
            
            if time_diff <= 0:
                continue
                
            # Calculate distance
            distance = calculate_distance(
                float(current['Latitude']),
                float(current['Longitude']),
                float(next_login['Latitude']),
                float(next_login['Longitude'])
            )
            
            # Calculate speed
            speed = distance / time_diff if time_diff > 0 else float('inf')
            
            if speed > speed_threshold:
                # Get IP info for assessment
                ip1_info = {
                    'org': current.get('ISP', ''),
                    'domain': current.get('Domain', ''),
                    'vpn': current.get('VPN', False),
                    'proxy': current.get('Proxy', False),
                    'hosting': current.get('Hosting', False)
                }
                ip2_info = {
                    'org': next_login.get('ISP', ''),
                    'domain': next_login.get('Domain', ''),
                    'vpn': next_login.get('VPN', False),
                    'proxy': next_login.get('Proxy', False),
                    'hosting': next_login.get('Hosting', False)
                }
                
                likelihood = assess_travel_likelihood(ip1_info, ip2_info)
                
                suspicious_patterns.append({
                    'UserPrincipalName': user,
                    'Time1': current['CreatedDateTime'],
                    'Location1': f"{current['City']}, {current['Country']}",
                    'IP1': current['ClientIPAddress'],
                    'Time2': next_login['CreatedDateTime'],
                    'Location2': f"{next_login['City']}, {next_login['Country']}",
                    'IP2': next_login['ClientIPAddress'],
                    'Distance': round(distance, 2),
                    'TimeDiff': round(time_diff, 2),
                    'Speed': round(speed, 2),
                    'Likelihood': likelihood,
                    'IP1_Info': current.get('ISP', ''),
                    'IP2_Info': next_login.get('ISP', '')
                })

    # Display patterns
    if suspicious_patterns:
        print("\nSuspicious Login Patterns:")
        for i, pattern in enumerate(suspicious_patterns[:max_display], 1):
            pattern_str = format_suspicious_pattern(pattern, 'login')
            print(f"\n{i}. {pattern_str}")
            
        remaining = len(suspicious_patterns) - max_display
        if remaining > 0:
            print(f"\n...and {remaining} more suspicious login patterns.")
    else:
        print("\nNo suspicious login patterns detected.")
        
    print(f"\nTotal suspicious login patterns: {len(suspicious_patterns)}")
    return suspicious_patterns


def detect_session_impossible_travel(
    session_data: Dict[str, List[Dict[str, Any]]], 
    max_display: int = 5,
    speed_threshold: float = 1000
) -> List[Dict[str, Any]]:
    """Detect impossible travel patterns from session data."""
    suspicious_patterns = []

    # Process each session's events
    for session_id, events in session_data.items():
        if len(events) < 2:
            continue

        # Sort events by timestamp
        sorted_events = sorted(
            events,
            key=lambda x: datetime.fromisoformat(
                x['CreatedDateTime'].replace('Z', '+00:00')
            )
        )

        # Compare consecutive events
        for i in range(len(sorted_events) - 1):
            current = sorted_events[i]
            next_event = sorted_events[i + 1]

            # Skip if missing location data
            if not all([
                current.get('Latitude'), current.get('Longitude'),
                next_event.get('Latitude'), next_event.get('Longitude')
            ]):
                continue

            # Calculate time difference
            time1 = datetime.fromisoformat(
                current['CreatedDateTime'].replace('Z', '+00:00')
            )
            time2 = datetime.fromisoformat(
                next_event['CreatedDateTime'].replace('Z', '+00:00')
            )
            time_diff = (time2 - time1).total_seconds() / 3600

            if time_diff <= 0:
                continue

            # Calculate distance
            distance = calculate_distance(
                float(current['Latitude']),
                float(current['Longitude']),
                float(next_event['Latitude']),
                float(next_event['Longitude'])
            )

            # Calculate speed
            speed = distance / time_diff if time_diff > 0 else float('inf')

            if speed > speed_threshold:
                # Get IP info for assessment
                ip1_info = {
                    'org': current.get('ISP', ''),
                    'domain': current.get('Domain', ''),
                    'vpn': current.get('VPN', False),
                    'proxy': current.get('Proxy', False),
                    'hosting': current.get('Hosting', False)
                }
                ip2_info = {
                    'org': next_event.get('ISP', ''),
                    'domain': next_event.get('Domain', ''),
                    'vpn': next_event.get('VPN', False),
                    'proxy': next_event.get('Proxy', False),
                    'hosting': next_event.get('Hosting', False)
                }
                
                likelihood = assess_travel_likelihood(ip1_info, ip2_info)
                
                suspicious_patterns.append({
                    'SessionId': session_id,
                    'Time1': current['CreatedDateTime'],
                    'Operation1': current['Operation'],
                    'Location1': f"{current['City']}, {current['Country']}",
                    'IP1': current['ClientIPAddress'],
                    'Time2': next_event['CreatedDateTime'],
                    'Operation2': next_event['Operation'],
                    'Location2': f"{next_event['City']}, {next_event['Country']}",
                    'IP2': next_event['ClientIPAddress'],
                    'Distance': round(distance, 2),
                    'TimeDiff': round(time_diff, 2),
                    'Speed': round(speed, 2),
                    'Likelihood': likelihood,
                    'IP1_Info': current.get('ISP', ''),
                    'IP2_Info': next_event.get('ISP', '')
                })

    # Display patterns
    if suspicious_patterns:
        print("\nSuspicious Session Patterns:")
        for i, pattern in enumerate(suspicious_patterns[:max_display], 1):
            pattern_str = format_suspicious_pattern(pattern, 'session')
            print(f"\n{i}. {pattern_str}")

        remaining = len(suspicious_patterns) - max_display
        if remaining > 0:
            print(f"\n...and {remaining} more suspicious session patterns.")
    else:
        print("\nNo suspicious session patterns detected.")

    print(f"\nTotal suspicious session patterns: {len(suspicious_patterns)}")
    return suspicious_patterns


def process_audit_data(input_file: str, output_file: str):
    """Process audit data from input CSV file and save results."""
    try:
        # Create timestamped directories
        dirs = create_output_directories(output_file)
        
        # Update output paths
        combined_output = os.path.join(dirs['analysis'], 'extracted_data.csv')
        
        # Load and process the audit data
        df = pd.read_csv(input_file)
        
        # Loading rogue apps
        rogue_apps = load_rogue_apps()
        
        # Validate required columns
        required_columns = {'auditData', 'createdDateTime', 'operation'}
        if not required_columns.issubset(df.columns):
            missing = required_columns - set(df.columns)
            raise ValueError(f"Missing required columns: {missing}")
            
        total_rows = len(df)
        extracted_data = []
        ip_cache = load_ip_cache()
        ip_queue = set()  # Set to collect unique IPs for batch processing

        print("\nProcessing audit data...")
        print(f"Found columns: {', '.join(df.columns)}")

        # Pre-parse timestamps for better performance
        df['parsed_datetime'] = pd.to_datetime(df['createdDateTime'])
        
        # First pass: collect unique IPs and process them
        print("\nCollecting unique IP addresses...")
        for index, row in df.iterrows():
            try:
                if pd.isna(row['auditData']):
                    continue
                    
                fields = extract_fields_from_json(row['auditData'])
                client_ip = fields[1]  # client_ip is the second field

                # If no client_ip in auditData, try using the one from CSV
                if not client_ip and 'clientIp' in df.columns:
                    client_ip = row['clientIp']

                # Validate and process IP address
                if client_ip:
                    ip_data = process_ip_address(client_ip)
                    if ip_data and ip_data['ip'] not in ip_cache:
                        ip_queue.add(ip_data['ip'])

                if index > 0 and index % 1000 == 0:
                    msg = (
                        f"Processed {index}/{total_rows} rows "
                        f"({len(ip_queue)} new IPs)"
                    )
                    print(msg)

            except Exception as e:
                print(f"Error processing row {index}: {str(e)}")

        # Batch process IP info
        if ip_queue:
            ip_count = len(ip_queue)
            print(f"\nFetching info for {ip_count} new IP addresses...")
            failed_ips = []
            for i, ip in enumerate(ip_queue):
                if ip not in ip_cache:
                    try:
                        ip_info = get_ip_info(ip, ip_cache)
                    except Exception as e:
                        print(f"Failed to get info for IP {ip}: {str(e)}")
                        failed_ips.append(ip)
                        continue

                    if (i + 1) % 10 == 0:
                        save_ip_cache(ip_cache)
                        print(f"Progress: {i + 1}/{ip_count}")

            if failed_ips:
                fail_count = len(failed_ips)
                print(f"\nWarning: Failed to get info for {fail_count} IPs")

            # Final save of new IP info
            save_ip_cache(ip_cache)

        # Second pass: extract data with cached IP info
        print("\nExtracting audit data...")
        for index, row in df.iterrows():
            try:
                if pd.isna(row['auditData']):
                    continue
                    
                fields = extract_fields_from_json(row['auditData'])
                (
                    aad_session_id, client_ip, session_id,
                    subject, object_id, site_url, source_filename, app_id, client_app_id
                ) = fields

                # If no client_ip in auditData, try using the one from CSV
                if not client_ip and 'clientIp' in df.columns:
                    client_ip = row['clientIp']

                # Get session ID even if no IP is present
                effective_session_id = get_effective_session_id(
                    session_id,
                    aad_session_id
                )

                # Process IP address if present
                ip_data = process_ip_address(client_ip) if client_ip else None
                ip_info = {}
                
                if ip_data:
                    ip_info = ip_cache.get(ip_data['ip'], {})
                    
                

                # extracted data
                entry = {
                    'ID': row['id'],
                    'CreatedDateTime': row['createdDateTime'],
                    'parsed_datetime': row['parsed_datetime'],
                    'Operation': row['operation'],
                    'ClientIPAddress': ip_data['ip'] if ip_data else '',
                    'ClientIPPort': ip_data['port'] if ip_data else None,
                    'IPType': ip_data['type'] if ip_data else '',
                    'OriginalIP': ip_data['original'] if ip_data else '',
                    'EffectiveSessionId': effective_session_id,
                    'Subject': subject,
                    'ObjectId': object_id or row.get('objectId', ''),
                    'SiteUrl': site_url,
                    'SourceFilename': source_filename,
                    'AppId': app_id,                    # Add AppId
                    'ClientAppId': client_app_id,       # Add ClientAppId
                    'IsRogueApp': bool(
                            app_id in rogue_apps or 
                            client_app_id in rogue_apps
                        ) if rogue_apps else False,
                    'RogueAppName': (
                            rogue_apps.get(app_id, {}).get('name') or
                            rogue_apps.get(client_app_id, {}).get('name', '')
                        ) if rogue_apps else '',
                    'RogueSeverity': (
                            rogue_apps.get(app_id, {}).get('severity') or
                            rogue_apps.get(client_app_id, {}).get('severity', '')
                        ) if rogue_apps else '',
                    'City': ip_info.get('city', ''),
                    'Region': ip_info.get('region', ''),
                    'Country': ip_info.get('country', ''),
                    'Latitude': ip_info.get('latitude', ''),
                    'Longitude': ip_info.get('longitude', ''),
                    'ISP': ip_info.get('org', ''),
                    'Domain': ip_info.get('domain', ''),
                    'VPN': ip_info.get('vpn', False),
                    'Proxy': ip_info.get('proxy', False),
                    'Hosting': ip_info.get('hosting', False),
                    'HasIP': bool(ip_data)  # Add flag to indicate IP presence
                }
                extracted_data.append(entry)

                if index > 0 and index % 1000 == 0:
                    progress = (index + 1) / total_rows * 100
                    curr_row = index + 1
                    msg = (
                        f"Progress: {progress:.1f}% "
                        f"({curr_row}/{total_rows})"
                    )
                    print(msg)

            except Exception as e:
                print(f"Error processing row {index}: {str(e)}")

        # Create DataFrame from extracted data
        result_df = pd.DataFrame(extracted_data)
        
        # Save results to new directories
        result_df.to_csv(combined_output, index=False)
        
        # 0. Save rogue apps to CSV
        rogue_apps_output = save_rogue_app_detections(
            extracted_data,
            dirs['analysis']
        )
        
        # 1. Save session-specific data
        combined_output, session_files = save_session_data(
            extracted_data,
            dirs['sessions']
        )
        
        # 2. Save operation groups
        operation_files = save_operation_groups(
            extracted_data,
            dirs['operations']
        )
        
        # 3. Save analysis results
        risk_output = os.path.join(dirs['analysis'], 'risk_analysis.csv')
        travel_output = os.path.join(dirs['analysis'], 'impossible_travel.csv')
        login_out = os.path.join(dirs['analysis'], 'login_impossible.csv')
        session_out = os.path.join(dirs['analysis'], 'session_impossible.csv')
        
        # 4. Analyze session risks and save
        session_risks, impossible_events = analyze_session_risks(extracted_data)
        save_risk_analysis(session_risks, risk_output)
        
        # 5. Save impossible travel analysis
        save_impossible_travel_analysis(
            impossible_events,
            travel_output
        )
        
        # 6. Process login-based impossible travel
        login_impossible = detect_login_impossible_travel(result_df)
        if login_impossible:
            login_df = pd.DataFrame(login_impossible)
            login_df.to_csv(login_out, index=False)
            print(f"\nLogin impossible travel saved to: {login_out}")
        
        # 7. Process session-based impossible travel
        session_data = {
            entry['EffectiveSessionId']: []
            for entry in extracted_data
        }
        for entry in extracted_data:
            session_id = entry['EffectiveSessionId']
            session_data[session_id].append(entry)
            
        session_impossible = detect_session_impossible_travel(session_data)
        if session_impossible:
            session_df = pd.DataFrame(session_impossible)
            session_df.to_csv(session_out, index=False)
            print(f"\nSession impossible travel saved to: {session_out}")

        # Save all events without filtering
        all_events_output = save_all_events(
            extracted_data,
            dirs['analysis']
        )
        
        # Print summary with new paths
        print("\nProcessing Summary:")
        print(f"Output directory: {dirs['base']}")
        print(f"- All events file: {os.path.basename(all_events_output)}")
        print(f"- Combined data file: {os.path.basename(combined_output)}")
        print(f"- Session files: {len(session_files)} (in session_files/)")
        print(f"- Operation files: {len(operation_files)} (in operation_groups/)")
        print(f"- Analysis results saved in: analysis_results/")
        
    except Exception as e:
        print(f"Error processing audit data: {str(e)}")
        raise


def format_suspicious_pattern(
    pattern: Dict[str, Any],
    pattern_type: str = "login"
) -> str:
    """Format a suspicious pattern for concise terminal output."""
    if pattern_type == "login":
        return (
            f"Login Pattern - User: {pattern['UserPrincipalName']}\n"
            f"  {pattern['Time1']}: {pattern['Location1']} ({pattern['IP1']})\n"
            f"  {pattern['Time2']}: {pattern['Location2']} ({pattern['IP2']})\n"
            f"  Speed: {pattern['Speed']} km/h, Distance: {pattern['Distance']} km\n"
            f"  Assessment: {pattern['Likelihood']}\n"
            f"  IP1 Info: {pattern['IP1_Info']}\n"
            f"  IP2 Info: {pattern['IP2_Info']}"
        )
    else:
        return (
            f"Session Pattern - ID: {pattern['SessionId']}\n"
            f"  {pattern['Time1']} ({pattern['Operation1']}): {pattern['Location1']}\n"
            f"  {pattern['Time2']} ({pattern['Operation2']}): {pattern['Location2']}\n"
            f"  Speed: {pattern['Speed']} km/h, Distance: {pattern['Distance']} km\n"
            f"  Assessment: {pattern['Likelihood']}\n"
            f"  IP1 Info: {pattern['IP1_Info']}\n"
            f"  IP2 Info: {pattern['IP2_Info']}"
        )


def process_ip_address(ip_str: str) -> Optional[Dict[str, Any]]:
    """
    Process and validate an IP address string.
    Extracts IP and port if present, validates IP version.
    Handles both IPv4 and IPv6 addresses with proper validation.
    
    Args:
        ip_str: String containing IP address, optionally with port number
        
    Returns:
        Dictionary with processed IP information or None if invalid
    """
    if not ip_str or pd.isna(ip_str):
        return None
        
    try:
        # Convert to string if not already
        ip_str = str(ip_str).strip()
        if not ip_str:
            return None

        # Handle IPv6 with port
        if '[' in ip_str and ']' in ip_str:
            # Extract IPv6 address and port
            ip = ip_str[ip_str.find('[')+1:ip_str.find(']')]
            port_str = ip_str[ip_str.find(']')+1:]
            if port_str.startswith(':'):
                port = int(port_str[1:])
                if port < 0 or port > 65535:
                    print(f"Invalid port number in IPv6 address {ip_str}")
                    return None
            else:
                port = None
        else:
            # Handle IPv4 with port or IPv6 without port
            if ip_str.count(':') > 1:
                # This is an IPv6 address without brackets
                ip = ip_str
                port = None
            else:
                # This might be IPv4 with port
                ip_parts = ip_str.rsplit(':', 1)
                ip = ip_parts[0]
                port = None
                if len(ip_parts) > 1 and ip_parts[1].isdigit():
                    port = int(ip_parts[1])
                    if port < 0 or port > 65535:
                        print(f"Invalid port number in IP {ip_str}")
                        return None
        
        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            ip_type = 'IPv6' if is_ipv6 else 'IPv4'
            # Get normalized form of IP address
            ip = str(ip_obj)
        except ValueError as e:
            print(f"Invalid IP address: {ip} ({str(e)})")
            return None
            
        return {
            'ip': ip,
            'port': port,
            'type': ip_type,
            'original': ip_str
        }
        
    except Exception as e:
        print(f"Error processing IP address {ip_str}: {str(e)}")
        return None


def is_microsoft_ip(ip_info: Dict[str, Any]) -> bool:
    """Check if IP belongs to Microsoft."""
    microsoft_indicators = [
        'microsoft',
        'msft',
        'azure',
        'office365',
        'outlook'
    ]
    org = ip_info.get('org', '').lower()
    domain = ip_info.get('domain', '').lower()
    return any(
        indicator in org or indicator in domain
        for indicator in microsoft_indicators
    )


def assess_travel_likelihood(
    ip1_info: Dict[str, Any],
    ip2_info: Dict[str, Any]
) -> str:
    """Assess the likelihood of impossible travel being a false positive."""
    
    # Check if either IP is from Microsoft
    if is_microsoft_ip(ip1_info) or is_microsoft_ip(ip2_info):
        return "Unlikely (Microsoft IP)"
    
    # Check if either IP is a VPN/proxy
    if (ip1_info.get('vpn') or ip2_info.get('vpn') or 
        ip1_info.get('proxy') or ip2_info.get('proxy')):
        return "Possible (VPN/Proxy)"
    
    # Check if either IP is from hosting/cloud
    if ip1_info.get('hosting') or ip2_info.get('hosting'):
        return "Possible (Cloud/Hosting)"
        
    return "Likely"
    

def create_output_directories(base_output_file: str) -> Dict[str, str]:
    """Create timestamped output directories for analysis results."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_dir = os.path.dirname(base_output_file)
    
    # Create main output directory with timestamp
    output_dir = os.path.join(base_dir, f'audit_analysis_{timestamp}')
    subdirs = {
        'sessions': os.path.join(output_dir, 'session_files'),
        'operations': os.path.join(output_dir, 'operation_groups'),
        'analysis': os.path.join(output_dir, 'analysis_results')
    }
    
    # Create all directories
    for directory in [output_dir] + list(subdirs.values()):
        os.makedirs(directory, exist_ok=True)
        
    return {
        'base': output_dir,
        **subdirs
    }
    

def save_all_events(
    extracted_data: List[Dict[str, Any]],
    base_dir: str
) -> str:
    """Save all events to a single CSV file without any filtering."""
    try:
        all_events_output = os.path.join(
            base_dir,
            'all_events.csv'
        )
        
        # Convert to DataFrame and save
        df = pd.DataFrame(extracted_data)
        df.to_csv(all_events_output, index=False)
        print(f"\nAll events saved to: {all_events_output}")
        print(f"Total events: {len(extracted_data)}")
        
        return all_events_output
    except Exception as e:
        print(f"Error saving all events: {str(e)}")
        return None


def load_rogue_apps(filename: str = 'Rogue Applications.csv') -> Dict[str, Dict[str, str]]:
    """Load rogue applications data from CSV."""
    
    if not os.path.exists(filename):
        print(f"\nWarning: Rogue applications file not found: {filename}")
        print("Rogue application detection will be skipped.")
        return {}
    try:
        df = pd.read_csv(filename)
        return {
            row['AppId']: {
                'name': row['AppDisplayName'],
                'severity': row['Severity']
            }
            for _, row in df.iterrows()
        }
    except Exception as e:
        print(f"Error loading rogue applications: {str(e)}")
        return {}


def save_rogue_app_detections(
    extracted_data: List[Dict[str, Any]],
    analysis_dir: str
) -> str:
    """Save rogue application detections to a separate CSV file."""
    try:
        # Filter for rogue app detections
        rogue_detections = []
        for entry in extracted_data:
            if entry.get('IsRogueApp'):
                detection = {
                    'Timestamp': entry['CreatedDateTime'],
                    'User': entry['Subject'],
                    'Operation': entry['Operation'],
                    'AppId': entry['AppId'],
                    'ClientAppId': entry['ClientAppId'],
                    'AppName': entry['RogueAppName'],
                    'Severity': entry['RogueSeverity'],
                    'ClientIPAddress': entry['ClientIPAddress'],
                    'Location': f"{entry['City']}, {entry['Country']}",
                    'SessionId': entry['EffectiveSessionId']
                }
                rogue_detections.append(detection)

        if rogue_detections:
            output_file = os.path.join(analysis_dir, 'rogue_app_detections.csv')
            df = pd.DataFrame(rogue_detections)
            df.to_csv(output_file, index=False)
            print(f"\nRogue app detections saved to: {output_file}")
            print(f"Total rogue app detections: {len(rogue_detections)}")
            return output_file
        else:
            print("\nNo rogue app detections found")
            return None

    except Exception as e:
        print(f"Error saving rogue app detections: {str(e)}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            'Extract audit data fields from CSV file and detect '
            'suspicious patterns'
        )
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path',
        default='audit_analysis.csv'
    )
    parser.add_argument(
        'input_file',
        help='Input CSV file with audit data'
    )

    args = parser.parse_args()
    output_file = args.output or 'audit_analysis.csv'
    process_audit_data(args.input_file, output_file)

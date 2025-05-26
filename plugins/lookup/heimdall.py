"""heimdall.py

An ansible-rulebook event source plugin for HEIMDALL2 vulnerability management.

This plugin polls a HEIMDALL2 server for security evaluation results and emits
events for failed security controls that can trigger automated remediation.

Arguments:
  - heimdall_url: HEIMDALL2 server URL (required)
  - api_key: API key for authentication (required, can use HEIMDALL_API_KEY env var)
  - poll_interval: Seconds between polling cycles (optional, default: 300)
  - ssl_verify: Whether to verify SSL certificates (optional, default: false)
  - target_controls: List of specific control IDs to monitor (optional, monitors all if empty)

Examples:
  sources:
    - heimdall:
        heimdall_url: "https://heimdall.example.com"
        api_key: "your-api-key"
        poll_interval: 300
        ssl_verify: false
        target_controls:
          - "xccdf_org.ssgproject.content_rule_sshd_enable_warning_banner"

Events Generated:
  - heimdall2_startup: Plugin initialization
  - heimdall2_connectivity: API connectivity status  
  - heimdall2_vulnerability: Failed security controls
  - heimdall2_error: Error conditions
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timezone
import os
from typing import Any, Dict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FIXED: Added required argument metadata dictionary
argument_spec = dict(
    heimdall_url=dict(type="str", required=True),
    api_key=dict(type="str", required=False, default=""),
    poll_interval=dict(type="int", required=False, default=300),
    ssl_verify=dict(type="bool", required=False, default=False),
    target_controls=dict(type="list", required=False, default=[])  # Empty list = check all controls
)

async def main(queue: asyncio.Queue, args: Dict[str, Any]):
    """
    Main function for EDA source plugin - REQUIRED ENTRY POINT
    
    Args:
        queue: Event queue to put events into
        args: Configuration dictionary from rulebook
    """
    
    # Extract configuration with defaults
    heimdall_url = args.get('heimdall_url', '').rstrip('/')
    api_key = args.get('api_key', os.getenv('heimdall_api_key', ''))
    poll_interval = int(args.get('poll_interval', 300))
    ssl_verify = bool(args.get('ssl_verify', False))
    target_controls = args.get('target_controls', [])
    
    logger.info(f"Starting HEIMDALL2 plugin with URL: {heimdall_url}")
    
    # Basic validation
    if not heimdall_url:
        error_event = {
            'heimdall2_error': {
                'type': 'configuration',
                'message': 'heimdall_url is required but not provided',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        await queue.put(error_event)
        logger.error("No heimdall_url provided")
        return
        
    if not api_key:
        error_event = {
            'heimdall2_error': {
                'type': 'configuration',
                'message': 'API key is required but not provided',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        await queue.put(error_event)
        logger.error("No API key provided")
        return
    
    # Emit startup event
    startup_event = {
        'heimdall2_startup': {
            'url': heimdall_url,
            'poll_interval': poll_interval,
            'target_controls_count': len(target_controls),
            'ssl_verify': ssl_verify,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': 'HEIMDALL2 source plugin started successfully'
        }
    }
    await queue.put(startup_event)
    await asyncio.sleep(0)  # Give CPU cycles to event loop
    logger.info("Startup event emitted")
    
    # HTTP client setup
    headers = {
        'Authorization': f'Api-Key {api_key}',
        'Accept': 'application/json',
        'User-Agent': 'AAP-EDA-HEIMDALL2/1.0'
    }
    
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    connector = aiohttp.TCPConnector(ssl=ssl_verify)
    
    # State tracking
    processed_findings = set()
    poll_count = 0
    
    try:
        async with aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=timeout
        ) as session:
            
            # Test connectivity first
            connectivity_ok = await test_connectivity(session, heimdall_url, queue)
            if not connectivity_ok:
                logger.error("Connectivity test failed, but continuing...")
            
            # Main polling loop
            while True:
                try:
                    poll_count += 1
                    logger.info(f"Starting poll #{poll_count}")
                    
                    # Poll for evaluations
                    await poll_evaluations(
                        session, 
                        heimdall_url, 
                        queue, 
                        processed_findings, 
                        target_controls,
                        poll_count
                    )
                    
                    # Clean up processed findings periodically
                    if len(processed_findings) > 1000:
                        processed_findings.clear()
                        logger.info("Cleared processed findings cache")
                    
                    logger.info(f"Poll #{poll_count} completed, sleeping for {poll_interval} seconds")
                    await asyncio.sleep(poll_interval)
                    
                except asyncio.CancelledError:
                    logger.info("Polling cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in poll #{poll_count}: {e}")
                    
                    error_event = {
                        'heimdall2_error': {
                            'type': 'polling',
                            'message': str(e),
                            'poll_count': poll_count,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    }
                    await queue.put(error_event)
                    await asyncio.sleep(0)
                
                    # Back off on errors
                    await asyncio.sleep(min(poll_interval, 60))
                    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        fatal_event = {
            'heimdall2_error': {
                'type': 'fatal',
                'message': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        await queue.put(fatal_event)

async def test_connectivity(session, heimdall_url, queue):
    """Test API connectivity with simple endpoint"""
    
    try:
        # Try a simpler endpoint first
        test_url = f"{heimdall_url}/status"
        
        logger.info(f"Testing connectivity to status endpoint: {test_url}")
        
        try:
            async with session.get(test_url) as response:
                logger.info(f"Status endpoint response: {response.status}")
                if response.status == 200:
                    # Success with status endpoint
                    connectivity_event = {
                        'heimdall2_connectivity': {
                            'status': 'success',
                            'url': heimdall_url,
                            'status_code': response.status,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    }
                    await queue.put(connectivity_event)
                    return True
        except Exception as e:
            logger.warning(f"Status endpoint failed, trying evaluations endpoint: {e}")
        
        # Fall back to evaluations endpoint with minimal parameters
        test_url = f"{heimdall_url}/evaluations"
        params = {
            'limit': 1
        }
        
        logger.info(f"Testing connectivity to: {test_url}")
        
        async with session.get(test_url, params=params) as response:
            logger.info(f"Connectivity test response: {response.status}")
            
            if response.status == 200:
                # Test response structure
                try:
                    data = await response.json()
                    logger.info(f"API response structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                    
                except Exception as json_err:
                    logger.error(f"Error parsing connectivity test response: {json_err}")
                
                connectivity_event = {
                    'heimdall2_connectivity': {
                        'status': 'success',
                        'url': heimdall_url,
                        'status_code': response.status,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                }
                await queue.put(connectivity_event)
                return True
            else:
                error_text = await response.text()
                logger.error(f"Connectivity failed: {response.status} - {error_text}")
                
                # Despite the error, return true to continue testing
                # This allows the plugin to continue even with connectivity issues
                error_event = {
                    'heimdall2_error': {
                        'type': 'connectivity',
                        'message': f"HTTP {response.status}: {error_text[:200]}",
                        'status_code': response.status,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                }
                await queue.put(error_event)
                return True  # Changed to True to continue despite error
                
    except Exception as e:
        logger.error(f"Connectivity test exception: {e}")
        
        error_event = {
            'heimdall2_error': {
                'type': 'connectivity',
                'message': f"Connection failed: {str(e)}",
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        await queue.put(error_event)
        return True  # Changed to True to continue despite error

async def poll_evaluations(session, heimdall_url, queue, processed_findings, target_controls, poll_count):
    """Poll HEIMDALL2 for evaluations"""
    
    api_url = f"{heimdall_url}/evaluations"
    
    # FIXED: Use MultiDict from correct package
    from multidict import MultiDict
    params = MultiDict([
        ('offset', 0),
        ('limit', 100),  # Increased from 10
        ('groupId', 1),  # Added groupId parameter
        ('order[]', 'createdAt'),
        ('order[]', 'DESC')
    ])
    
    try:
        logger.info(f"Polling evaluations from: {api_url}")
        async with session.get(api_url, params=params) as response:
            logger.info(f"Evaluations API response: {response.status}")
            
            if response.status != 200:
                error_text = await response.text()
                logger.error(f"API error response: {error_text[:500]}")
                
                error_event = {
                    'heimdall2_error': {
                        'type': 'api',
                        'message': f"API error: HTTP {response.status} - {error_text[:200]}",
                        'status_code': response.status,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                }
                await queue.put(error_event)
                return
                
            data = await response.json()
            logger.info(f"API response structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
            
            if 'evaluations' not in data:
                logger.warning("No 'evaluations' key in API response")
                logger.debug(f"Full response: {json.dumps(data, indent=2)[:1000]}")
                return
            
            evaluations = data['evaluations']
            total_count = data.get('totalCount', len(evaluations))
            logger.info(f"Retrieved {len(evaluations)} evaluations (total: {total_count})")
            
            # Process each evaluation
            for i, evaluation in enumerate(evaluations):
                logger.info(f"Processing evaluation {i+1}/{len(evaluations)}: ID {evaluation.get('id', 'unknown')}")
                try:
                    await process_evaluation(
                        session, 
                        heimdall_url, 
                        evaluation, 
                        queue, 
                        processed_findings, 
                        target_controls
                    )
                except Exception as e:
                    logger.error(f"Error processing evaluation {evaluation.get('id', 'unknown')}: {e}")
                    
    except Exception as e:
        logger.error(f"Exception in poll_evaluations: {e}")
        error_event = {
            'heimdall2_error': {
                'type': 'api',
                'message': f"Polling failed: {str(e)}",
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        await queue.put(error_event)

async def process_evaluation(session, heimdall_url, evaluation, queue, processed_findings, target_controls):
    """Process individual evaluation"""
    
    eval_id = evaluation.get('id')
    if not eval_id:
        logger.warning("Evaluation missing ID")
        return
    
    logger.info(f"Processing evaluation ID: {eval_id}")
    eval_url = f"{heimdall_url}/evaluations/{eval_id}"
    
    try:
        async with session.get(eval_url) as response:
            if response.status != 200:
                logger.warning(f"Failed to get evaluation {eval_id}: {response.status}")
                error_text = await response.text()
                logger.debug(f"Error response: {error_text[:200]}")
                return
                
            eval_data = await response.json()
            logger.debug(f"Evaluation {eval_id} structure: {list(eval_data.keys()) if isinstance(eval_data, dict) else type(eval_data)}")
            
            # Try different possible response structures
            profiles_data = None
            
            if isinstance(eval_data, dict):
                if 'data' in eval_data and 'profiles' in eval_data['data']:
                    profiles_data = eval_data['data']['profiles']
                elif 'profiles' in eval_data:
                    profiles_data = eval_data['profiles']
                elif 'data' in eval_data and isinstance(eval_data['data'], dict):
                    # Look for profiles in nested data
                    nested_data = eval_data['data']
                    if 'profiles' in nested_data:
                        profiles_data = nested_data['profiles']
            
            if not profiles_data:
                logger.warning(f"Evaluation {eval_id} has no profiles data")
                logger.debug(f"Available keys: {list(eval_data.keys()) if isinstance(eval_data, dict) else 'not a dict'}")
                return
            
            # Extract host information
            host_info = extract_host_info(eval_data, eval_id)
            logger.info(f"Host info: {host_info}")
            
            # Extract findings from profiles
            findings = extract_findings_from_profiles(profiles_data, target_controls)
            logger.info(f"Found {len(findings)} findings for evaluation {eval_id}")
            
            # Emit events for new findings - SIMPLIFIED FOR DEMO
            timestamp = evaluation.get('createdAt', datetime.now(timezone.utc).isoformat())
            for finding in findings:
                finding_key = f"{host_info['hostname']}:{finding['control']}:{eval_id}"
                
                if finding_key not in processed_findings:
                    processed_findings.add(finding_key)
                    
                    # Simplified event with essential information
                    vulnerability_event = {
                        'heimdall2_vulnerability': {
                            'hostname': host_info['hostname'],
                            'control': finding['control'],
                            'status': finding.get('status', 'failed'),  # Include status
                            'timestamp': timestamp
                        }
                    }
                    
                    logger.info(f"Emitting vulnerability event: {finding['control']} on {host_info['hostname']}")
                    await queue.put(vulnerability_event)
                    await asyncio.sleep(0)  # Give CPU cycles to event loop
                else:
                    logger.debug(f"Skipping already processed finding: {finding_key}")
                    
    except Exception as e:
        logger.error(f"Error processing evaluation {eval_id}: {e}")

def extract_host_info(eval_data, eval_id):
    """Extract host information from evaluation"""
    
    try:
        # Try multiple possible locations for profile data
        profiles = None
        
        if isinstance(eval_data, dict):
            if 'data' in eval_data and 'profiles' in eval_data['data']:
                profiles = eval_data['data']['profiles']
            elif 'profiles' in eval_data:
                profiles = eval_data['profiles']
        
        if not profiles or len(profiles) == 0:
            # Use filename or fallback to eval_id
            filename = eval_data.get('filename', f'evaluation-{eval_id}')
            return {
                'hostname': filename,
                'platform': 'unknown',
                'target_id': ''
            }
        
        profile = profiles[0]
        platform = profile.get('platform', {})
        
        # Try multiple ways to get hostname
        hostname = (
            platform.get('hostname') or
            platform.get('name') or 
            eval_data.get('filename', '').split('.')[0] or
            f'evaluation-{eval_id}'
        )
        
        return {
            'hostname': hostname,
            'platform': platform.get('name', 'unknown'),
            'target_id': platform.get('target_id', '')
        }
        
    except Exception as e:
        logger.error(f"Error extracting host info: {e}")
        return {
            'hostname': f'evaluation-{eval_id}',
            'platform': 'unknown', 
            'target_id': ''
        }

def extract_findings_from_profiles(profiles_data, target_controls):
    """Extract failed control findings from profiles data"""
    
    findings = []
    target_controls_set = set(target_controls) if target_controls else set()
    
    try:
        if not isinstance(profiles_data, list):
            logger.warning(f"Profiles data is not a list: {type(profiles_data)}")
            return findings
        
        # Debug: Show what controls we're looking for
        if target_controls_set:
            logger.info(f"Looking for these target controls: {target_controls_set}")
        else:
            logger.info("No specific target controls - checking all controls")
        
        for profile in profiles_data:
            if not isinstance(profile, dict):
                continue
                
            # Check for different structures in Heimdall responses
            if 'controls' in profile:
                controls = profile.get('controls', [])
            elif 'rules' in profile:
                controls = profile.get('rules', [])
            else:
                controls = []
                
            logger.info(f"Profile has {len(controls)} controls")
            
            # Debug: Count status types
            status_counts = {}
            
            for control in controls:
                if not isinstance(control, dict):
                    continue
                    
                control_id = control.get('id')
                if not control_id:
                    continue
                
                # Filter by target controls if specified - do this FIRST
                if target_controls_set and control_id not in target_controls_set:
                    continue
                
                # Look for failure indicators in multiple places
                failed = False
                
                # Method 1: Check results array
                results = control.get('results', [])
                if results and isinstance(results, list):
                    for result in results:
                        if isinstance(result, dict) and result.get('status') == 'failed':
                            failed = True
                            break
    
                # Method 2: Check status directly on control
                if not failed and control.get('status') == 'failed':
                    failed = True
    
                # Method 3: Check overall status on control
                if not failed and control.get('overall_status') == 'failed':
                    failed = True
                    
                if failed:
                    logger.info(f"Found failed control: {control_id}")
                    findings.append({
                        'control': control_id,
                        'status': 'failed'
                    })
    
            # Log status distribution
            logger.info(f"Control status distribution: {status_counts}")
                
    except Exception as e:
        logger.error(f"Error extracting findings: {e}")
    
    return findings

def determine_severity(impact):
    """Convert impact score to severity level"""
    try:
        impact_float = float(impact)
        if impact_float >= 0.7:
            return 'HIGH'
        elif impact_float >= 0.5:
            return 'MEDIUM'
        elif impact_float >= 0.3:
            return 'LOW'
        else:
            return 'INFO'
    except (ValueError, TypeError):
        return 'UNKNOWN'

def clean_description(desc):
    """Clean and truncate description text"""
    if not desc:
        return 'No description available'
    
    # Remove extra whitespace
    cleaned = ' '.join(str(desc).split())
    
    # Truncate if too long
    if len(cleaned) > 500:
        return cleaned[:500] + '...'
    
    return cleaned

# For testing
if __name__ == "__main__":
    
    class MockQueue:
        async def put(self, event):
            event_type = list(event.keys())[0]
            if event_type == 'heimdall2_vulnerability':
                data = event[event_type]
                print(f"\n=== FAILED SECURITY CONTROL ===")
                print(f"Host: {data.get('hostname')}")
                print(f"Control: {data.get('control')}")
                print(f"Status: {data.get('status', 'failed')}")  # Display status
                print(f"Date: {data.get('timestamp')}")
            else:
                print(f"\n=== {event_type.upper()} EVENT ===")
                for key, value in event[event_type].items():
                    print(f"{key}: {value}")
    
    async def test_run():
        # Test configuration with real values
        test_args = {
            'heimdall_url': '{{ heimdall_url }}',
            'api_key': '{{ heimdall_api_key }}',
            'poll_interval': 30,  # Shorter for testing
            'ssl_verify': False,
            'target_controls': []  # Empty list = check all controls
        }
        
        print("Starting HEIMDALL2 plugin test...")
        await main(MockQueue(), test_args)
    
    # THIS LINE IS NOW UNCOMMENTED:
    asyncio.run(test_run())

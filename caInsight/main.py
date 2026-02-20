"""
Main CLI entry point for CA Insight Python
"""

import argparse
import json
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .analyzer.evaluator import PolicyEvaluator
from .analyzer.mapper import UserMapper
from .analyzer.permutations import PermutationGenerator
from .analyzer.policy_flattener import PolicyFlattener
from .analyzer.coverage_detector import CoverageDetector
from .filter_config import FilterConfig
from .graph.api_client import GraphAPIClient
from .reports.generator import ReportGenerator


def cache_has_valid_content(cache_file: Path) -> bool:
    """Check if cache file exists and contains valid non-empty data.
    
    Parameters:
        cache_file: Path to cache file
        
    Returns:
        bool: True if file exists and contains meaningful data, False otherwise
    """
    if not cache_file.exists():
        return False
    
    try:
        # Check if file is too small (just [] or {})
        if cache_file.stat().st_size < 10:
            return False
        
        # Load and check if data is empty
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Check if data is empty list or dict
        if isinstance(data, (list, dict)) and not data:
            return False
            
        return True
    except (json.JSONDecodeError, IOError):
        # If we can't read/parse the file, treat it as invalid
        return False


def populate_caches(
    policies: List[Dict],
    api_client: GraphAPIClient,
    assignment_type: str = None,
    target_resources: str = None,
    progress_callback: Optional[Callable] = None
) -> None:
    """
    Populate object caches from policies.
    
    Populates all missing object caches regardless of scan type, as all caches
    are needed for the policy browser.
    
    Parameters:
        policies: List of filtered CA policies relevant for gap analysis
        api_client: Graph API client for fetching objects
        progress_callback: Optional callback for progress updates
    """
    cache_dir = Path("cache")
    cache_dir.mkdir(exist_ok=True)
    
    # Check which caches are missing
    caches_needed = []

    # === Tenant-level caches ===

    # Scan-specific caches: Assignment types
    if assignment_type == 'users':
        if not cache_has_valid_content(cache_dir / "tenant" / "active-members.json"):
            caches_needed.append('active-users')
    elif assignment_type == 'guests':
        if not cache_has_valid_content(cache_dir / "tenant" / "active-guests.json"):
            caches_needed.append('active-guests')
    elif assignment_type == 'agent-identities':
        if not cache_has_valid_content(cache_dir / "tenant" / "active-agent-identities.json"):
            caches_needed.append('active-agent-identities')
    elif assignment_type == 'workload-identities':
        if not cache_has_valid_content(cache_dir / "tenant" / "active-workload-identities.json"):
            caches_needed.append('active-workload-identities')

    # === Policy-level caches used by the Policy Browser (necessary regardless of scan type) ===

    # Assignments
    if not cache_has_valid_content(cache_dir / "policies" / "users.json"):
        caches_needed.append('users')
    if not cache_has_valid_content(cache_dir / "policies" / "groups.json"):
        caches_needed.append('groups')
    if not cache_has_valid_content(cache_dir / "policies" / "roles.json"):
        caches_needed.append('roles')
    if not cache_has_valid_content(cache_dir / "policies" / "agent-identities.json"):
        caches_needed.append('agent_identities')
    if not cache_has_valid_content(cache_dir / "policies" / "service-principals.json"):    # used for workload identities
        caches_needed.append('service_principals')
    
    # Target resources
    if not cache_has_valid_content(cache_dir / "policies" / "applications.json"):
        caches_needed.append('applications')
    if not cache_has_valid_content(cache_dir / "policies" / "agent-resources.json"):
        caches_needed.append('agent-resources')
    
    # Authentication contexts
    if not cache_has_valid_content(cache_dir / "policies" / "auth-contexts.json"):
        caches_needed.append('auth_contexts')

    # If all caches exist, skip population
    if not caches_needed:
        if progress_callback:
            progress_callback(25, "✓ All necessary caches already exist")
        return
    
    if progress_callback:
        progress_callback(25, f"Populating caches...")
    
    # === POPULATE CACHES ===
    mapper = UserMapper(api_client)
    
    # Scan-specific caches: Assignment types
    if 'active-users' in caches_needed:
        api_client.get_all_active_members(use_cache=False)
    elif 'active-guests' in caches_needed:
        api_client.get_all_active_guests(use_cache=False)
    elif 'active-agent-identities' in caches_needed:
        api_client.get_all_active_agent_identities(use_cache=False)
    elif 'active-workload-identities' in caches_needed:
        api_client.get_all_active_workload_identities(use_cache=False)

    # Assignment identities
    if 'users' in caches_needed:
        mapper.populate_users_cache(policies, progress_callback=progress_callback)
    
    if 'groups' in caches_needed:
        mapper.populate_groups_cache(policies, progress_callback=progress_callback)
    
    if 'roles' in caches_needed:
        mapper.populate_roles_cache(policies, progress_callback=progress_callback)
    
    if 'agent_identities' in caches_needed:
        mapper.populate_agent_identities_cache(policies, progress_callback=progress_callback)

    if 'service_principals' in caches_needed:
        mapper.populate_service_principals_cache(policies, progress_callback=progress_callback)

    # Target resources
    if 'applications' in caches_needed:
        mapper.populate_applications_cache(policies, progress_callback=progress_callback)
    
    if 'agent_resources' in caches_needed:
        mapper.populate_agent_resources_cache(policies, progress_callback=progress_callback)

    # Extra for Policy Browser
    if 'auth_contexts' in caches_needed:
        mapper.populate_auth_contexts_cache(policies, progress_callback=progress_callback)
    
    if progress_callback:
        progress_callback(25, f"✓ Caches populated")


def handle_critical_gap_scenario(
    token: str,
    api_client: GraphAPIClient,
    source: str,
    config: Dict,
    all_policies: List[Dict],
    named_locations: List[Dict],
    filter_stats: Dict,
    progress_callback: Optional[Callable],
    start_time: float,
    flattened_policies: List[Dict] = None
) -> Dict:
    """Handle critical scenario when no policies with strong controls match the analysis criteria.
    
    Creates a single critical gap report indicating complete lack of protection for the scenario.
    
    Args:
        token: MS Graph access token
        api_client: Graph API client instance
        source: Source of the analysis ('cli' or 'web')
        config: Analysis configuration dictionary
        all_policies: List of all CA policies (for policy browser)
        named_locations: List of named location objects
        filter_stats: Policy filtering statistics
        progress_callback: Optional callback for progress updates
        start_time: Analysis start timestamp
        flattened_policies: Flattened policies (empty list if no policies match criteria)
        
    Returns:
        Dictionary with analysis results indicating critical gap
    """
    if progress_callback:
        progress_callback(25, "⚠️ CRITICAL: No policy with strong controls match this scenario")
        progress_callback(26, "Creating critical gap...")
    
    # Count named locations (exclude 'All' and 'AllTrusted')
    locations_count = len(named_locations)
    
    # Count client app types - Static set: 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'
    client_types_count = 4
    
    # Determine the correct target resource key and count based on scan type
    target_resource_type = config.get('target_resources')
    if target_resource_type == 'cloud-apps':
        target_key = 'resourceApps'
        target_display = 'all'
        # Count applications from cache
        generator_perm = PermutationGenerator()
        application_ids = generator_perm._load_resource_ids_from_cache(
            Path('cache') / 'tenant' / 'active-cloud-apps.json'
        )
        target_count = len(application_ids)
    elif target_resource_type == 'user-actions':
        target_key = 'userActions'
        target_display = 'all'
        target_count = 2  # registerSecurityInformation and registerOrJoinDevices
    elif target_resource_type == 'agent-resources':
        target_key = 'agentResources'
        target_display = 'all'
        # Count agent resources from cache
        generator_perm = PermutationGenerator()
        agent_resource_ids = generator_perm._load_resource_ids_from_cache(
            Path('cache') / 'tenant' / 'active-agent-resources.json'
        )
        target_count = len(agent_resource_ids)
    
    # Determine the correct identity key based on assignment type
    assignment_type = config.get('assignments')
    if assignment_type == 'users':
        identity_key = 'users'
        identity_display = 'all'
    elif assignment_type == 'guests':
        identity_key = 'guests'
        identity_display = 'all'
    elif assignment_type == 'agent-identities':
        identity_key = 'agents'
        identity_display = 'all'
    elif assignment_type == 'workload-identities':
        identity_key = 'workloadIdentities'
        identity_display = 'all'
    else:
        identity_key = 'users'
        identity_display = 'all'
    
    # Calculate universal coverage statistics for critical gap scenario
    cache_dir = Path("cache")
    all_identity_ids = set()
    
    if assignment_type == 'users':
        cache_file = cache_dir / "tenant" / "active-members.json"
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                all_active_users = json.load(f)
                all_identity_ids = set([user.get('id') for user in all_active_users])
    elif assignment_type == 'guests':
        # For user-actions, only include internal/local guests (user actions apply to home tenant)
        if target_resource_type == 'user-actions':
            cache_file = cache_dir / "tenant" / "internal-guests.json"
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    internal_guests = json.load(f)
                    all_identity_ids = set([guest.get('id') for guest in internal_guests])
        else:
            cache_file = cache_dir / "tenant" / "active-guests.json"
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    all_active_guests = json.load(f)
                    all_identity_ids = set([guest.get('id') for guest in all_active_guests])
    elif assignment_type == 'agent-identities':
        cache_file = cache_dir / "tenant" / "active-agent-identities.json"
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                all_active_agents = json.load(f)
                all_identity_ids = set([agent.get('id') for agent in all_active_agents])
    elif assignment_type == 'workload-identities':
        # Workload identities are stored in service-principals.json in the policies folder
        cache_file = cache_dir / "policies" / "service-principals.json"
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                all_service_principals = json.load(f)
                # Filter for workload identities: servicePrincipalType == 'Application' and accountEnabled == true
                workload_identities = [
                    sp for sp in all_service_principals 
                    if sp.get('servicePrincipalType') == 'Application' 
                    and sp.get('accountEnabled') == True
                ]
                all_identity_ids = set([sp.get('id') for sp in workload_identities])
    
    # Get identity count for the permutation
    identity_count = len(all_identity_ids)
    
    # Create a single critical gap with all dimensions set to 'all'
    critical_gap = {
        'permutation': {
            identity_key: {'id': 'all', 'displayName': identity_display, 'type': 'all', 'count': identity_count},
            target_key: {'id': 'all', 'displayName': target_display, 'type': 'all', 'count': target_count},
            'clientAppTypes': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': client_types_count},
            'locations': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': locations_count}
        },
        'lineage': f"{config.get('assignments', 'any')} → {config.get('target_resources', 'any')} (all conditions)",
        'terminated': False,  
        'is_universal_gap': True
    }
    
    # Build list of critical gaps (typically just one, but may have multiple for special cases)
    critical_gaps = []
    
    # Special case: For guests + user-actions, create specific gaps per uncovered user action
    if assignment_type == 'guests' and target_resource_type == 'user-actions':
        # Check which user actions have universal coverage (use empty list if no policies)
        detector = CoverageDetector()
        action_coverage = detector.detect_user_action_coverage_for_guests(flattened_policies or [])
        
        # Get internal (local) guest count
        internal_guests_cache = cache_dir / "tenant" / "internal-guests.json"
        internal_guest_count = 0
        if internal_guests_cache.exists():
            with open(internal_guests_cache, 'r', encoding='utf-8') as f:
                internal_guests = json.load(f)
                internal_guest_count = len(internal_guests)
        
        # Create gap for registerSecurityInfo if not covered (applies to local guests only)
        if not action_coverage.get('urn:user:registersecurityinfo', False) and internal_guest_count > 0:
            register_security_info_gap = {
                'permutation': {
                    'guests': {'id': 'internal-guests', 'displayName': 'Local guest users', 'type': 'internal-guests', 'count': internal_guest_count},
                    'userActions': {'id': 'registerSecurityInformation', 'displayName': 'Register Security Information', 'type': 'user-action', 'count': 1},
                    'clientAppTypes': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': client_types_count},
                    'locations': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': locations_count}
                },
                'lineage': f"Local guest users → Register Security Information (all conditions)",
                'terminated': False,
                'is_universal_gap': True  # Mark as universal gap for consistent styling
            }
            critical_gaps.append(register_security_info_gap)
        
        # Create gap for registerDevice if not covered (applies only to local guests)
        if not action_coverage.get('urn:user:registerdevice', False) and internal_guest_count > 0:
            local_guest_device_gap = {
                'permutation': {
                    'guests': {'id': 'internal-guests', 'displayName': 'Local guest users', 'type': 'internal-guests', 'count': internal_guest_count},
                    'userActions': {'id': 'registerOrJoinDevices', 'displayName': 'Register Device', 'type': 'user-action', 'count': 1},
                    'clientAppTypes': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': client_types_count},
                    'locations': {'id': 'all', 'displayName': 'all', 'type': 'all', 'count': locations_count}
                },
                'lineage': f"Local guest users → Register Device (all conditions)",
                'terminated': False,
                'is_universal_gap': True  # Mark as universal gap for consistent styling
            }
            critical_gaps.append(local_guest_device_gap)
    else:
        # For other scenarios, use the generic critical gap
        critical_gaps = [critical_gap]
    
    # For critical gap: zero coverage, all identities exposed
    universal_coverage_stats = {
        'total_identities': len(all_identity_ids),
        'mfa_covered': 0,
        'auth_strength_covered': 0,
        'block_covered': 0,
        'identities_with_gaps': len(all_identity_ids),
        'mfa_coverage_pct': 0.0,
        'auth_strength_coverage_pct': 0.0,
        'block_coverage_pct': 0.0
    }
    
    # Write JSON with single critical gap
    generator = ReportGenerator(
        token=token, 
        api_client=api_client, 
        source=source, 
        assignment=config.get('assignments'),
        target_resource=config.get('target_resources'),
        progress_callback=progress_callback
    )
    
    # Use custom filename if provided, otherwise auto-generate with correct format
    custom_filename = f"{config.get('output')}.json" if config.get('output') else None
    # For critical gap scenario, all identities are exposed
    critical_filter_stats = {
        'total_identities_in_tenant': len(all_identity_ids),
        'included_users_count': len(all_identity_ids),
        'excluded_users_count': 0
    }
    
    result_path = generator.generate_json_report(
        results=critical_gaps,
        policies=all_policies,
        excluded_policies=filter_stats.get('excluded_policies', []),
        filename=custom_filename,
        progress_callback=progress_callback,
        universal_coverage_stats=universal_coverage_stats,
        analysis_start_time=start_time,
        analysis_end_time=time.time(),
        filter_statistics=critical_filter_stats
    )
    
    if progress_callback:
        progress_callback(90, f"✓ Critical gap created")

    # Generate portal with critical warning
    portal_path = generator.generate_portal_with_policy_browser(
        policies=all_policies,
        named_locations=[],
        mapper=None
    )
    
    runtime = time.time() - start_time
    
    return {
        'success': True,
        'result_path': str(result_path),
        'portal_path': str(portal_path),
        'gaps_count': 1,  # Single critical gap
        'permutations_count': 1,
        'runtime': runtime,
        'critical': True  # Flag for callers
    }


def run_analysis(token: str, config: Dict, progress_callback=None, source: str = 'cli') -> Dict:
    """Run CA Insight analysis with given configuration.
    
    This function can be called programmatically from the web interface or CLI.
    
    Args:
        token: MS Graph access token
        config: Analysis configuration dictionary with keys:
            - assignments: 'users-groups-roles', 'agent-identities', or 'workload-identities'
            - target_resources: 'cloud-apps', 'user-actions', or 'agent-resources'
            - conditions: list of condition options (optional)
            - threads: number of worker threads (default: 10)
            - output: output filename prefix (optional)
            - debug: whether to dump debug files (default: False)
            - filter_config: FilterConfig instance or dict with 'include'/'exclude' lists (optional)
            - clear_cache: whether to clear cache (default: False)
        progress_callback: Optional callback function(percent, message) for progress updates
        source: Source of the analysis ('cli' or 'web') for filename generation
        
    Returns:
        Dictionary with:
            - success: bool
            - result_path: path to JSON results
            - portal_path: path to portal HTML
            - gaps_count: number of gaps found
            - permutations_count: number of permutations analyzed
            - error: error message if success=False
    """
    try:
        # === INIT ===
        start_time = time.time()
        
        # Initialize API client
        proxy = config.get('proxy', None)
        api_client = GraphAPIClient(token, proxy=proxy)
        
        # Validate token
        is_valid, error_msg = api_client.validate_token()
        if is_valid:
            if progress_callback:
                progress_callback(5, "✓ Access token is valid")
        else:
            return {'success': False, 'error': f"Invalid token: {error_msg}"}
        
        # Clear cache if requested
        clear_cache_mode = config.get('clear_cache')
        if clear_cache_mode:
            mapper = UserMapper(api_client)
            mapper.clear_mapping_cache(mode=clear_cache_mode)
            if progress_callback:
                cache_type = {'all': 'all caches', 'policies': 'policy caches', 'tenant': 'tenant caches'}.get(clear_cache_mode, 'cache')
                progress_callback(8, f"✓ Cleared caches - {cache_type}")

        # Fetch all policies
        clear_cache_mode = config.get('clear_cache')
        all_policies = api_client.get_all_policies(use_cache=not bool(clear_cache_mode))       
        if progress_callback:
            progress_callback(12, f"✓ Fetched {len(all_policies)} policies")

        # Fetch all named locations
        named_locations = api_client.get_named_locations(use_cache=not (clear_cache_mode in ['all', 'tenant']))
        if progress_callback:
            progress_callback(17, f"✓ Fetched {len(named_locations)} named locations")

        # Filter out policies relying on weak controls or that are not suited for the type of requested scan
        clear_cache_mode = config.get('clear_cache')
        policies_for_gap_analysis, filter_stats = api_client.get_policies_for_gap_analysis(
            use_cache=not bool(clear_cache_mode),
            debug=False,
            assignment_type=config.get('assignments'),
            target_resource=config.get('target_resources')
        )
        if progress_callback:
            total_filtered = filter_stats['total_policies'] - filter_stats['passed'] - filter_stats['disabled_policies']
            progress_callback(21, f"✓ Policy filtering applied: {filter_stats['total_policies']:_} total, {filter_stats['disabled_policies']:_} disabled, {total_filtered} filtered out, {filter_stats['passed']:_} for gap analysis".replace('_', ' '))

        # Populate object caches based on scan type
        populate_caches(
            policies=policies_for_gap_analysis,
            assignment_type=config.get('assignments'),
            target_resources=config.get('target_resources'),
            api_client=api_client,
            progress_callback=progress_callback
        )

        # === DETECT NO POLICY BLIND SPOT ===

        # No policies match criteria
        # E.g. tenant has ZERO policies with strong controls for the specified assignment/target resource
        if not policies_for_gap_analysis:
            return handle_critical_gap_scenario(
                token=token,
                api_client=api_client,
                source=source,
                config=config,
                all_policies=all_policies,
                named_locations=named_locations,
                filter_stats=filter_stats,
                progress_callback=progress_callback,
                start_time=start_time,
                flattened_policies=[]
            )
        

        # === MAIN WORKFLOW ===

        # Step 1: Flatten policies to resolve groups/roles to member IDs
        assignments = config.get('assignments')
        
        if progress_callback:
            progress_callback(26, "Flattening policies (resolving groups and roles to members)...")
        
        flattener = PolicyFlattener(api_client)
        non_resolvable_guest_coverage = {}  # Track coverage for non-resolvable guest types
        
        if assignments == 'users':
            flattened_policies = flattener.flatten_policies_for_users(policies_for_gap_analysis,
                                                                      target_resources=config.get('target_resources'),
                                                                      progress_callback=progress_callback)
            identity_type = 'users'
        elif assignments == 'guests':
            flattened_policies, non_resolvable_guest_coverage = flattener.flatten_policies_for_guests(
                policies_for_gap_analysis,
                target_resources=config.get('target_resources'),
                progress_callback=progress_callback
            )
            identity_type = 'users'
        elif assignments == 'agent-identities':
            flattened_policies = flattener.flatten_policies_for_agents(policies_for_gap_analysis,
                                                                      target_resources=config.get('target_resources'),
                                                                      progress_callback=progress_callback)
            identity_type = 'agents'
        else:  # workload-identities
            flattened_policies = flattened_policies = flattener.flatten_policies_for_workloads(policies_for_gap_analysis,
                                                                      target_resources=config.get('target_resources'),
                                                                      progress_callback=progress_callback)
            identity_type = 'workloadIdentities'
        
        if progress_callback:
            progress_callback(30, f"✓ Flattened policies")

        # Step 2: Detect universal coverage (identities covered by universal policies)
        if progress_callback:
            progress_callback(32, "Detecting universal policy coverage...")
        
        detector = CoverageDetector()

        if assignments == 'users':
            mfa_covered, auth_strength_covered, block_covered = detector.detect_universal_coverage_for_users(
                flattened_policies,
                target_resource=config.get('target_resources')
            )
        elif assignments == 'guests':
            mfa_covered, auth_strength_covered, block_covered = detector.detect_universal_coverage_for_guests(
                flattened_policies,
                target_resource=config.get('target_resources')
            )
        elif assignments == 'agent-identities':
            universally_covered = detector.detect_universal_coverage_for_agents(
                flattened_policies,
                target_resource=config.get('target_resources')
            )
            # Agent identities only support block control for now
            mfa_covered = set()
            auth_strength_covered = set()
            block_covered = universally_covered
        else:  # workload-identities
            universally_covered = detector.detect_universal_coverage_for_workloads(
                flattened_policies,
                target_resource=config.get('target_resources')
            )
            # Workload identities only support block control for now
            mfa_covered = set()
            auth_strength_covered = set()
            block_covered = universally_covered
        
        # Apply filter_config early to determine which identities to retrieve and analyze
        filter_config = config.get('filter_config')
        
        # Resolve groups and roles to user IDs if filter config has them
        if filter_config and (len(filter_config.include_groups) > 0 or len(filter_config.include_roles) > 0 or 
                             len(filter_config.exclude_groups) > 0 or len(filter_config.exclude_roles) > 0):
            if progress_callback:
                progress_callback(30, "Resolving filter groups and roles to user IDs...")
            filter_config.resolve_groups_and_roles(api_client)
        
        # Always retrieve all active identities from tenant to get accurate total
        if assignments == 'users':
            all_active_users = api_client.get_all_active_members(use_cache=True)
            all_identity_ids = set([user.get('id') for user in all_active_users])
        elif assignments == 'guests':
            # For user-actions, only include internal/local guests (user actions apply to home tenant)
            if config.get('target_resources') == 'user-actions':
                internal_guests = api_client.get_internal_guests(use_cache=True)
                all_identity_ids = set([guest.get('id') for guest in internal_guests])
            else:
                # Include all guest users (userType=Guest) 
                all_active_guest_users = api_client.get_all_active_guests(use_cache=True)
                all_identity_ids = set([guest.get('id') for guest in all_active_guest_users])

                # Include all B2B collaboration members (userType=Member from external tenants)
                b2b_members = api_client.get_b2b_collaboration_members(use_cache=True)
                all_identity_ids.update([member.get('id') for member in b2b_members if member.get('id')])
        elif assignments == 'agent-identities':
            all_active_agent_identities = api_client.get_all_active_agent_identities(use_cache=True)
            all_identity_ids = set([agent.get('id') for agent in all_active_agent_identities])
        else:  # workload-identities
            all_active_workload_identities = api_client.get_all_active_workload_identities(use_cache=True)
            all_identity_ids = set([workload.get('id') for workload in all_active_workload_identities])
            
            # Fallback: if active-workload-identities cache is empty, use service-principals.json
            if not all_identity_ids:
                sp_cache_file = Path("cache") / "policies" / "service-principals.json"
                if sp_cache_file.exists():
                    with open(sp_cache_file, 'r', encoding='utf-8') as f:
                        all_service_principals = json.load(f)
                        # Filter for workload identities: servicePrincipalType == 'Application' and accountEnabled == true
                        workload_identities = [
                            sp for sp in all_service_principals 
                            if sp.get('servicePrincipalType') == 'Application' 
                            and sp.get('accountEnabled') == True
                        ]
                        all_identity_ids = set([sp.get('id') for sp in workload_identities])
        
        # Store total identities in tenant (before any filtering)
        total_identities_in_tenant = len(all_identity_ids)
        
        # Apply filters
        identities_to_analyze = all_identity_ids.copy()
        
        if filter_config and filter_config.has_include_filter():
            # Include filter: Only analyze identities in the include list
            identities_to_analyze = filter_config.include_ids.copy()
            
            if progress_callback:
                progress_callback(32, f"Using include filter...")
                progress_callback(33, f"✓ Include {len(identities_to_analyze)} identities out of {total_identities_in_tenant} in scope")
        elif filter_config and filter_config.has_exclude_filter():
            # Exclude filter: Remove excluded identities from analysis
            excluded_count = len(identities_to_analyze & filter_config.exclude_ids)
            identities_to_analyze = identities_to_analyze - filter_config.exclude_ids
            
            if progress_callback:
                progress_callback(32, f"Using exclude filter...")
                progress_callback(33, f"✓ Excluded {excluded_count} identities (analyzing {len(identities_to_analyze)} out of {total_identities_in_tenant})")
        
        # Calculate filter statistics for metadata
        filter_statistics = {
            'total_identities_in_tenant': total_identities_in_tenant,
            'included_users_count': len(identities_to_analyze),
            'excluded_users_count': total_identities_in_tenant - len(identities_to_analyze)
        }
        
        # From the identity set covered by universal policies, keep only active identities that are in scope for the analysis
        active_mfa_covered = mfa_covered & identities_to_analyze
        active_auth_strength_covered = auth_strength_covered & identities_to_analyze
        active_block_covered = block_covered & identities_to_analyze

        # Avoid double-counting identities covered by multiple types of universal policies
        # Make coverage sets mutually exclusive based on precedence: block > auth_strength > mfa
        unique_active_block_covered = active_block_covered
        unique_active_auth_strength_covered = active_auth_strength_covered - unique_active_block_covered
        unique_active_mfa_covered = active_mfa_covered - unique_active_auth_strength_covered - unique_active_block_covered
        universally_covered = unique_active_mfa_covered | unique_active_auth_strength_covered | unique_active_block_covered

        if progress_callback:
            if assignments in ['users', 'guests']:
                progress_callback(34, f"✓ Universal coverage: {len(unique_active_mfa_covered):_} MFA-only, {len(unique_active_auth_strength_covered):_} Auth Strength-only, {len(unique_active_block_covered):_} Blocked".replace('_', ' '))
            else:
                progress_callback(34, f"✓ Universal coverage: {len(universally_covered):_} identities blocked".replace('_', ' '))

        # Step 3: Get all identities and filter to potentially unprotected ones
        if progress_callback:
            progress_callback(36, "Identifying potentially unprotected identities...")

        potentially_unprotected_ids = set()
        if 'All' in universally_covered:
            # At least one universal policy covers ALL identities with a strong control (MFA, Auth Strength, or Block)
            pass
        else:
            potentially_unprotected_ids = identities_to_analyze - universally_covered
        
        if not potentially_unprotected_ids:
            # All identities are protected by universal policies - generate report with 0 gaps
            if progress_callback:
                progress_callback(80, "✓ All identities are protected by universal policies - no gaps found")
            
            # Build mapper for report generation (needed for policy browser)
            mapper = UserMapper(api_client)
            report_gen = ReportGenerator(
                token=token, 
                api_client=api_client, 
                source=source, 
                assignment=config.get('assignments'),
                target_resource=config.get('target_resources'),
                progress_callback=progress_callback
            )
            
            # Generate portal HTML
            portal_file = report_gen.generate_portal_with_policy_browser(
                all_policies, 
                named_locations,
                mapper
            )
            
            if progress_callback:
                progress_callback(90, "Generating JSON report...")
            
            # Prepare universal coverage statistics
            universal_coverage_stats = {
                'total_identities': len(identities_to_analyze),
                'mfa_covered': len(unique_active_mfa_covered),
                'auth_strength_covered': len(unique_active_auth_strength_covered),
                'block_covered': len(unique_active_block_covered),
                'identities_with_gaps': 0,  # No gaps found
                'mfa_coverage_pct': (len(unique_active_mfa_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0,
                'auth_strength_coverage_pct': (len(unique_active_auth_strength_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0,
                'block_coverage_pct': (len(unique_active_block_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0
            }
            
            # Generate JSON report with 0 gaps
            custom_filename = f"{config.get('output')}.json" if config.get('output') else None
            json_file = report_gen.generate_json_report(
                [],  # Empty gaps list
                named_locations,
                custom_filename,
                policies=policies_for_gap_analysis,
                excluded_policies=filter_stats.get('excluded_policies', []),
                progress_callback=progress_callback,
                universal_coverage_stats=universal_coverage_stats,
                analysis_start_time=start_time,
                analysis_end_time=time.time(),
                filter_statistics=filter_statistics
            )
            
            runtime = time.time() - start_time
            
            if progress_callback:
                progress_callback(100, "✓ Analysis complete")
            
            return {
                'success': True,
                'result_path': str(json_file),
                'portal_path': str(portal_file),
                'gaps_count': 0,
                'permutations_count': 0,
                'runtime': runtime
            }
        
        if progress_callback:
            reduction_pct = 100 * (1 - len(potentially_unprotected_ids) / len(identities_to_analyze)) if identities_to_analyze else 0
            progress_callback(38, f"✓ {len(potentially_unprotected_ids):_} potentially unprotected identities ({reduction_pct:.1f}% reduction)".replace('_', ' '))
        
        # Step 4: Generate per-identity permutations
        if progress_callback:
            progress_callback(40, "Generating per-identity permutations...")
        
        generator = PermutationGenerator()
        
        if assignments == 'users':
            identity_type = 'users'
            identity_permutations = generator.generate_permutations_for_users(
                list(potentially_unprotected_ids),
                target_resource=config.get('target_resources'),
                named_locations=named_locations
            )
        elif assignments == 'guests':
            identity_type = 'guests'
            # For user-actions target, get internal guests to filter device registration
            internal_guest_ids = set()
            if config.get('target_resources') == 'user-actions':
                internal_guests = api_client.get_internal_guests(use_cache=True)
                internal_guest_ids = set([g.get('id') for g in internal_guests])
            
            identity_permutations = generator.generate_permutations_for_guests(
                list(potentially_unprotected_ids),
                target_resource=config.get('target_resources'),
                named_locations=named_locations,
                internal_guest_ids=internal_guest_ids if internal_guest_ids else None
            )
        elif assignments == 'agent-identities':
            identity_type = 'agents'
            identity_permutations = generator.generate_permutations_for_agents(
                list(potentially_unprotected_ids),
                target_resource=config.get('target_resources')
            )
        else:  # workload-identities
            identity_type = 'workloadIdentities'
            identity_permutations = generator.generate_permutations_for_workloads(
                list(potentially_unprotected_ids),
                target_resource=config.get('target_resources'),
                named_locations=named_locations
            )
        
        total_permutations = sum(len(perms) for perms in identity_permutations.values())
        permutations_per_identity = int(total_permutations / len(identity_permutations))
        if progress_callback:
            progress_callback(45, f"✓ Generated {total_permutations:_} permutations across {len(identity_permutations):_} identities ({permutations_per_identity:_} per identity)".replace('_', ' '))
        
        # Step 5: Evaluate permutations with early termination (multi-threaded)
        if progress_callback:
            progress_callback(50, "Evaluating permutations against flattened policies...")
        
        evaluator = PolicyEvaluator()
        early_termination_pct = config.get('early_termination', 100)
        threads = config.get('threads', 10)
        
        all_gaps = []
        evaluated_identities = 0
        protected_identities = 0
        
        # Thread-safe counters and locks
        lock = threading.Lock()
        progress_counter = {'evaluated': 0, 'protected': 0}
        
        def evaluate_identity_worker(identity_id, permutations):
            """Worker function for evaluating a single identity (thread-safe)."""
            result = evaluator.evaluate_identity_permutations(
                identity_id=identity_id,
                identity_type=identity_type,
                permutations=permutations,
                flattened_policies=flattened_policies,
                early_termination_pct=early_termination_pct
            )
            
            # Update thread-safe counters
            with lock:
                progress_counter['evaluated'] += 1
                if result['is_protected']:
                    progress_counter['protected'] += 1
                
                # Update progress every 10% of identities
                if progress_callback and progress_counter['evaluated'] % max(1, len(identity_permutations) // 10) == 0:
                    pct_complete = 50 + int(30 * (progress_counter['evaluated'] / len(identity_permutations)))
                    progress_callback(pct_complete, f"Evaluated {progress_counter['evaluated']:_}/{len(identity_permutations):_} identities...".replace('_', ' '))
                
                # Optional: Log early termination statistics (within lock to prevent concurrent printing)
                if result.get('early_terminated'):
                    print(f"  ⚡ Early termination: {result['termination_reason']}", flush=True)
            
            return result
        
        # Execute evaluation in parallel using thread pool
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all identity evaluation tasks
            future_to_identity = {
                executor.submit(evaluate_identity_worker, identity_id, permutations): identity_id
                for identity_id, permutations in identity_permutations.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_identity):
                try:
                    # Get identity_id for this future before processing result
                    identity_id = future_to_identity[future]
                    result = future.result()
                    
                    if not result['is_protected']:
                        # Add gaps to results - format for report generator
                        for gap_perm in result['gaps']:
                            # Build lineage string from permutation
                            lineage_parts = []
                            for key, value in gap_perm.items():
                                if isinstance(value, dict):
                                    lineage_parts.append(f"{key}:{value.get('id', value)}")
                                else:
                                    lineage_parts.append(f"{key}:{value}")
                            lineage = '|'.join(lineage_parts)
                            
                            # Determine identity type from assignment type
                            if assignments == 'users':
                                identity_type_for_gap = 'user'
                            elif assignments == 'guests':
                                identity_type_for_gap = 'guests'
                            elif assignments == 'agent-identities':
                                identity_type_for_gap = 'agent_identity'
                            else:
                                identity_type_for_gap = 'workload_identity'
                            
                            # Determine if this is a universal gap (all dimensions must be universal)
                            location_is_universal = gap_perm.get('location') in ['All', None]  # Universal if 'All' or not present
                            resource_is_universal = (
                                gap_perm.get('application') in ['All', 'AllAgentIdResources'] or  # Cloud apps or agent resources
                                gap_perm.get('userAction') == 'All'  # User actions
                            )
                            client_app_is_universal = gap_perm.get('clientAppType') in ['all', None]  # Universal if 'all' or not present
                            
                            is_universal = location_is_universal and resource_is_universal and client_app_is_universal
                            
                            # Build gap entry for report generator
                            gap_entry = {
                                'permutation': gap_perm,
                                'lineage': lineage,
                                'terminated': False,  # All gaps are not terminated (not protected)
                                'gap_source': identity_id,
                                'gap_source_type': identity_type_for_gap,
                                'is_universal_gap': is_universal
                            }
                            
                            # Thread-safe append
                            with lock:
                                all_gaps.append(gap_entry)
                except Exception as e:
                    error_identity_id = future_to_identity.get(future, "unknown")
                    error_msg = f"⚠️ Error evaluating identity {error_identity_id}: {str(e)}"
                    print(f"  {error_msg}")
                    if progress_callback:
                        progress_callback(None, error_msg)
        
        # Update final counters
        evaluated_identities = progress_counter['evaluated']
        
        # Immediately report progress after evaluation loop completes
        if progress_callback:
            progress_callback(81, "Processing gap results...")
        
        # === Add gaps for non-resolvable guest types without coverage ===
        if assignments == 'guests' and non_resolvable_guest_coverage:
            non_resolvable_type_names = {
                'b2bDirectConnectUser': 'B2B Direct Connect Users (shared channels)',
                'otherExternalUser': 'Other External Users',
                'serviceProvider': 'Service Provider Users (GDAP/CSP)'
            }
            
            for guest_type, has_coverage in non_resolvable_guest_coverage.items():
                if not has_coverage:
                    # Create a universal gap for this non-resolvable guest type
                    gap_entry = {
                        'permutation': {
                            'guests': {'id': guest_type, 'displayName': non_resolvable_type_names.get(guest_type, guest_type), 'type': 'non-resolvable-guest-type'},
                            'application': {'id': 'all', 'displayName': 'all', 'type': 'all'},
                            'clientAppType': {'id': 'all', 'displayName': 'all', 'type': 'all'},
                            'location': {'id': 'all', 'displayName': 'all', 'type': 'all'}
                        },
                        'lineage': f"{guest_type} → all applications (all conditions)",
                        'terminated': False,
                        'gap_source': guest_type,
                        'gap_source_type': 'non-resolvable-guest-type',
                        'is_universal_gap': True,
                        'is_non_resolvable_guest_type': True
                    }
                    all_gaps.append(gap_entry)
                    
                    if progress_callback:
                        progress_callback(81, f"⚠️ Gap: No coverage for {non_resolvable_type_names.get(guest_type, guest_type)}")
        
        gaps_count = len(all_gaps)
        permutations_count = total_permutations
        threads = config.get('threads', 10)  # For report generation ID resolution
        
        # Calculate protected identities: total evaluated minus identities with gaps
        identities_with_gaps_set = set()
        for gap in all_gaps:
            gap_source = gap.get('gap_source')
            if gap_source:
                identities_with_gaps_set.add(gap_source)
        protected_identities = evaluated_identities - len(identities_with_gaps_set)
        
        if progress_callback:
            progress_callback(82, f"✓ Analyzed {permutations_count:_} permutations, found {gaps_count:_} gaps ({protected_identities:_} identities protected)".replace('_', ' '))
        

        # Build mapper for report generation (needed for ID resolution)
        mapper = UserMapper(api_client)
        
        report_gen = ReportGenerator(
            token=token, 
            api_client=api_client, 
            source=source, 
            assignment=config.get('assignments'),
            target_resource=config.get('target_resources'),
            progress_callback=progress_callback
        )
        
        # Generate portal HTML
        portal_file = report_gen.generate_portal_with_policy_browser(
            all_policies, 
            named_locations,
            mapper
        )
        
        # Generate JSON report
        if progress_callback:
            progress_callback(90, "Generating JSON report with display name resolution...")
        
        # Calculate actual unique identities with gaps from gap results
        unique_identities_with_gaps = set()
        for gap in all_gaps:
            gap_source = gap.get('gap_source')
            if gap_source:
                unique_identities_with_gaps.add(gap_source)
        
        # Prepare universal coverage statistics
        universal_coverage_stats = {
            'total_identities': len(identities_to_analyze),
            'mfa_covered': len(unique_active_mfa_covered),
            'auth_strength_covered': len(unique_active_auth_strength_covered),
            'block_covered': len(unique_active_block_covered),
            'identities_with_gaps': len(unique_identities_with_gaps),  # Actual identities with gaps after analysis
            'mfa_coverage_pct': (len(unique_active_mfa_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0,
            'auth_strength_coverage_pct': (len(unique_active_auth_strength_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0,
            'block_coverage_pct': (len(unique_active_block_covered) / len(identities_to_analyze) * 100) if identities_to_analyze else 0
        }
        
        # Use custom filename only if explicitly provided by user
        custom_filename = f"{config.get('output')}.json" if config.get('output') else None
        
        json_file = report_gen.generate_json_report(
            all_gaps, named_locations,
            custom_filename,
            policies=policies_for_gap_analysis,
            excluded_policies=filter_stats.get('excluded_policies', []),
            progress_callback=progress_callback,
            universal_coverage_stats=universal_coverage_stats,
            analysis_start_time=start_time,
            analysis_end_time=time.time(),
            filter_statistics=filter_statistics
        )
        
        # Write debug file if requested
        if config.get('debug'):
            debug_file = Path(json_file).parent / 'debug.json'
            if progress_callback:
                progress_callback(95, f"Writing debug file to {debug_file.name}...")
            
            # Build policy lookup map for quick access to policy names
            policy_map = {p['id']: p.get('displayName', p['id']) for p in policies_for_gap_analysis}
            
            # Format all results (gaps only in new workflow)
            debug_data = []
            for gap in all_gaps:
                debug_entry = {
                    'lineage': gap.get('lineage', ''),
                    'terminated': gap.get('terminated', False),
                    'gap_source': gap.get('gap_source'),
                    'gap_source_type': gap.get('gap_source_type'),
                    'is_universal_gap': gap.get('is_universal_gap', False)
                }
                debug_data.append(debug_entry)
            
            # Write debug file
            with open(debug_file, 'w', encoding='utf-8') as f:
                json.dump(debug_data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ Debug file written: {debug_file}")
        
        end_time = time.time()
        runtime = end_time - start_time
        
        if progress_callback:
            progress_callback(100, "✓ Analysis complete!")
        
        return {
            'success': True,
            'result_path': str(json_file),
            'portal_path': str(portal_file),
            'gaps_count': gaps_count,
            'permutations_count': permutations_count,
            'runtime': runtime
        }
        
    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        return {
            'success': False,
            'error': error_msg
        }


def main():
    """CLI entry point for CA Insight analysis."""
    start_time = time.time()
    start_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    parser = argparse.ArgumentParser(
        description='Find gaps in Conditional Access policies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ---------- [USER -> AI RESOURCE] Find gaps when 'Users, Groups, and Roles' access 'Agent resources' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources agent-resources
  
  ---------- [USER -> APP] Find gaps when 'Users, Groups, and Roles' access 'Cloud Apps' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources cloud-apps

  ---------- [USER -> USER ACTION] Find gaps when 'Users, Groups, and Roles' execute 'User actions' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources user-actions


  ---------- [GUEST USER -> AI RESOURCE] Find gaps when 'Guest/External users' access 'Agent resources' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments guests --target-resources agent-resources

  ---------- [GUEST USER -> APP] Find gaps when 'Guest/External users' access 'Cloud Apps' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments guests --target-resources cloud-apps
  
  ---------- [GUEST USER -> USER ACTION] Find gaps when 'Guest/External users' execute 'User actions' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments guests --target-resources user-actions


  ---------- [AI AGENT -> APP] Find gaps when 'Agent identities' access 'Cloud Apps' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments agent-identities --target-resources cloud-apps
  
  ---------- [AI AGENT -> AI RESOURCE] Find gaps when 'Agent identities' access 'Agent resources' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments agent-identities --target-resources agent-resources
    

  ---------- [WORKLOAD IDENTITY -> APP] Find gaps when 'Workload identities' access 'Cloud Apps' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments workload-identities --target-resources cloud-apps
    
  ---------- [WORKLOAD IDENTITY -> AI RESOURCE] Find gaps when 'Workload identities' access 'Agent resources' ---------
  python -m caInsight --token YOUR_TOKEN --include-assignments workload-identities --target-resources agent-resources


  ---------- [MISC OPTIONS] ---------
  # With early termination (stop after 50% of permutations if identity is protected)
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources cloud-apps --early-termination 50 

  # Exclude/Include specific identities using a filter file
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources cloud-apps --filter-file filter-example.json
  
  # Run with custom thread count and output filename
  python -m caInsight --token YOUR_TOKEN --include-assignments users --target-resources cloud-apps --threads 20 --output my_analysis.json
        """
    )
    
    # Authentication
    parser.add_argument('--token', required=True, help='Microsoft Graph access token (required)')
    
    # Assignment types
    parser.add_argument('--include-assignments', 
                       required=True,
                       choices=['agent-identities', 'guests', 'users', 'workload-identities'],
                       help='Which assignment types to include (required)')
    
    # Target resources
    parser.add_argument('--target-resources',
                       required=True,
                       choices=['agent-resources', 'cloud-apps', 'user-actions'],
                       help='Which target resources to analyze (required)')
    
    # Identity filtering
    parser.add_argument('--filter-file', help='Path to JSON file with identity include/exclude filters')
    
    # Early termination optimization
    parser.add_argument('--early-termination', type=int, metavar='PERCENT',
                       help='Stop evaluating an identity after PERCENT%% of permutations if no gaps found (0-100, default: 100 = evaluate all). Example: --early-termination 50 stops after 50%% if identity is protected.')
    
    # Performance and output
    parser.add_argument('--threads', type=int, default=10, help='Number of worker threads (default: 10)')
    parser.add_argument('--output', help='Output filename prefix (without extension)')
    
    # Debugging
    parser.add_argument('--proxy', metavar='HOST:PORT',
                       help='Route all HTTP requests through specified proxy (e.g. 127.0.0.1:8080) without certificate verification')
    parser.add_argument('--debug', action='store_true', help='Write debug files (permutations, etc.)')
    parser.add_argument('--clear-cache', 
                       choices=['all', 'policies', 'tenant'],
                       help='Clear cached data before analysis: "all" (everything), "policies" (policy-specific caches), or "tenant" (tenant-wide caches)')
    
    args = parser.parse_args()
    
    try:
        # Validate token format
        if not args.token or len(args.token) < 20:
            print("Error: Invalid token format")
            return 1
        
        # Validate agent identities compatibility
        if args.include_assignments == 'agent-identities':
            if args.target_resources not in ['cloud-apps', 'agent-resources']:
                print("Error: Agent identities can only target 'cloud-apps' or 'agent-resources'")
                print("       User actions are not applicable to agent identities.")
                return 1
        
        # Validate workload identities compatibility
        if args.include_assignments == 'workload-identities':
            if args.target_resources not in ['cloud-apps', 'agent-resources']:
                print("Error: Workload identities can only target 'cloud-apps' or 'agent-resources'")
                print("       User actions are not applicable to workload identities.")
                return 1
        
        # Load and validate filter configuration - WILL NEED IMPROVEMENTS!
        filter_cfg = None
        if args.filter_file:
            try:
                filter_cfg = FilterConfig.from_file(args.filter_file)
                is_valid, conflicts = filter_cfg.validate()
                if not is_valid:
                    print(f"\nError: Filter configuration has conflicts")
                    print(f"The following {len(conflicts)} ID(s) appear in both include and exclude lists:")
                    for conflict_id in conflicts[:10]:  # Show first 10
                        print(f"  - {conflict_id}")
                    if len(conflicts) > 10:
                        print(f"  ... and {len(conflicts) - 10} more")
                    return 1
                
                # Display filter summary
                if filter_cfg.has_include_filter():
                    print(f"  Include Filter:   {len(filter_cfg.include_ids)} ID(s)")
                if filter_cfg.has_exclude_filter():
                    print(f"  Exclude Filter:   {len(filter_cfg.exclude_ids)} ID(s)")
            except FileNotFoundError as e:
                print(f"\nError: {e}")
                return 1
            except (json.JSONDecodeError, ValueError) as e:
                print(f"\nError: Invalid filter file format: {e}")
                return 1
        
        # Build config dict for run_analysis()
        if args.include_assignments == 'users':
            # users: authFlows + clientAppTypes + locations (other conditions are weak or unreliable)
            conditions_to_use = ['auth-flows', 'clientAppTypes', 'locations']
        elif args.include_assignments == 'guests':
            # guests: same as users - authFlows + clientAppTypes + locations
            conditions_to_use = ['auth-flows', 'clientAppTypes', 'locations']
        elif args.include_assignments == 'agent-identities':
            # agent-identities: do not support any condition
            conditions_to_use = []
        else:  # workload-identities
            # workload-identities: locations is the only supported condition
            conditions_to_use = ['locations']

        config = {
            'assignments': args.include_assignments,
            'target_resources': args.target_resources,
            'conditions': conditions_to_use,
            'threads': args.threads,
            'output': args.output,
            'debug': args.debug,
            'clear_cache': args.clear_cache,
            'filter_config': filter_cfg,
            'early_termination': args.early_termination if hasattr(args, 'early_termination') and args.early_termination else 100,
            'proxy': args.proxy,
        }

        # Display analysis scope
        print(f"\n{'='*60}")
        print(f"CA Insight - Conditional Access Gap Analysis")
        print(f"{'='*60}")
        print(f"Started: {start_timestamp}")
        print(f"Threads: {args.threads}\n")
        print("Analysis Scope:")
        print(f"  Assignments:      {args.include_assignments}")
        print(f"  Target Resources: {args.target_resources}")
        print(f"  Conditions:       {", ".join(conditions_to_use)}")
        print(f"{'='*60}")
        # Define progress callback to print status updates
        def progress_callback(percent: int, message: str):
            # Only print messages (not percents) for CLI output
            if message:
                print(message)
        
        # Run the analysis using the unified function
        result = run_analysis(args.token, config, progress_callback=progress_callback, source='cli')
        
        # Check result
        if not result['success']:
            print(f"\nError: {result['error']}")
            return 1
        
        # Calculate and display runtime
        end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_runtime = result['runtime']
        
        # Format runtime nicely
        hours = int(total_runtime // 3600)
        minutes = int((total_runtime % 3600) // 60)
        seconds = int(total_runtime % 60)
        
        if hours > 0:
            runtime_str = f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            runtime_str = f"{minutes}m {seconds}s"
        else:
            runtime_str = f"{seconds}s"
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Summary")
        print(f"{'='*60}")
        print(f"Started:      {start_timestamp}")
        print(f"Finished:     {end_timestamp}")
        print(f"Runtime:      {runtime_str} ({total_runtime:.2f}s)")
        print(f"Permutations: {result['permutations_count']:_}".replace('_', ' '))
        print(f"Gaps Found:   {result['gaps_count']:_}".replace('_', ' '))
        print(f"\n💡 To view the web portal: python ./web/api_server.py\n")
        print(f"{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        return 1
    except ValueError as e:
        # ValueError is used for token and validation errors
        print(f"\nError: {e}")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

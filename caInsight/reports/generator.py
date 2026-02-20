"""
Report generation for gap analysis results
"""

# Standard library imports
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import List, Dict, Any

# Third-party imports
import jwt
import requests

# Special Conditional Access keywords that should not be resolved as object IDs
SPECIAL_CA_VALUES = {'All', 'AllTrusted', 'GuestsOrExternalUsers', 'AllAgentIdResources', 'None', 'unknownFutureValue'}


class ReportGenerator:
    """Generates JSON reports for gap analysis results"""
    
    def __init__(self, token: str = None, api_client = None, source: str = None, 
                 assignment: str = None, target_resource: str = None, progress_callback = None):
        """Initialize the report generator.
        
        Extracts tenant ID from the access token for use in report filenames.
        
        Parameters:
            token (str, optional): Microsoft Graph access token (JWT). Used to extract
                                  tenant ID for filename generation. Default is None.
            api_client (GraphAPIClient, optional): Graph API client for resolving object IDs
                                                   to display names. Default is None.
            source (str, optional): Source of the report ('cli' or 'web'). Included in
                                   filename for tracking. Default is None.
            assignment (str, optional): Assignment type ('users-groups-roles', 'agent-identities', 
                                       'workload-identities'). Used for folder and filename generation.
            target_resource (str, optional): Target resource type ('cloud-apps', 'user-actions', 
                                            'agent-resources'). Used for filename generation.
            progress_callback (callable, optional): Callback function(percent, message) for progress updates.
        """
        self.token = token
        self.api_client = api_client
        self.source = source
        self.assignment = assignment
        self.target_resource = target_resource
        self.progress_callback = progress_callback
        self.tenant_id = None
        
        if token:
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                self.tenant_id = decoded.get('tid')
            except Exception:
                pass
                
    def generate_json_report(self, results: List[Dict], named_locations: List[Dict] = None,
                            filename: str = None, policies: List[Dict] = None,
                            excluded_policies: List[Dict] = None, progress_callback = None,
                            universal_coverage_stats: Dict = None,
                            analysis_start_time: float = None, analysis_end_time: float = None,
                            filter_statistics: Dict = None) -> str:
        """Generate a JSON report with full policy details and control analysis.
        
        Creates a JSON file with comprehensive analysis including:
        - Resolved display names for all IDs
        - Full policy objects for terminated permutations
        - Control analysis and protection scoring
        - Session control details
        - Excluded policies with exclusion reasons
        - Universal coverage statistics (if provided)
        - Filter statistics (included/excluded user counts)
        
        Parameters:
            results (List[Dict]): Analysis results from GapAnalyzer
            named_locations (List[Dict], optional): Named location objects
            filename (str, optional): Custom output filename
            policies (List[Dict], optional): Full policy objects for enhanced detail
            excluded_policies (List[Dict], optional): Policies excluded from analysis with reasons
            progress_callback (callable, optional): Callback function(percent, message) for progress updates.
                                                   If provided, reports detailed progress from 90-100%.
            universal_coverage_stats (Dict, optional): Universal coverage statistics with counts and percentages
            analysis_start_time (float, optional): Analysis start timestamp (time.time() format)
            analysis_end_time (float, optional): Analysis end timestamp (time.time() format)
            filter_statistics (Dict, optional): Filter statistics with total_identities_in_tenant, included_users_count, excluded_users_count
        
        Returns:
            str: Path to the generated JSON file
        """
        # Use instance callback if not provided as parameter
        if progress_callback is None:
            progress_callback = self.progress_callback
        if not filename:
            filename = self._generate_filename("json")
        
        # Build location lookup
        loc_lookup = {loc.get('id'): loc.get('displayName', loc.get('id')) for loc in (named_locations or [])}
        
        # Load all cached objects from cache files (read-only, no API calls, no cache updates)
        id_cache = {}  # Maps object IDs to display names
        app_cache = {}  # Maps application IDs to display names
        
        # Helper function to load cache file
        def load_cache_file(file_path, primary_field='displayName', fallback_field=None):
            if not file_path.exists():
                return {}
            try:
                with open(file_path, 'r') as f:
                    objects = json.load(f)
                    cache = {}
                    for obj in objects:
                        obj_id = obj.get('id') or obj.get('appId')  # Support both id and appId
                        if obj_id:
                            name = obj.get(primary_field) or (obj.get(fallback_field) if fallback_field else None) or obj_id
                            cache[obj_id] = name
                    return cache
            except Exception:
                return {}
        
        # Helper function to load application cache
        def load_app_cache_file(file_path):
            if not file_path.exists():
                return {}
            try:
                with open(file_path, 'r') as f:
                    objects = json.load(f)
                    cache = {}
                    for obj in objects:
                        display_name = obj.get('displayName', obj.get('id', obj.get('appId', 'Unknown')))
                        # Index by both service principal id and appId for flexible lookup
                        if obj.get('id'):
                            cache[obj['id']] = display_name
                        if obj.get('appId'):
                            cache[obj['appId']] = display_name
                    return cache
            except Exception:
                return {}
        
        # Load identity caches (users, guests, groups, roles, service principals, auth contexts)
        cache_dir = Path('cache')
        id_cache.update(load_cache_file(cache_dir / 'tenant' / 'active-members.json', 'displayName', 'userPrincipalName'))
        id_cache.update(load_cache_file(cache_dir / 'tenant' / 'active-guests.json', 'displayName', 'userPrincipalName'))
        id_cache.update(load_cache_file(cache_dir / 'tenant' / 'active-agent-identities.json'))
        id_cache.update(load_cache_file(cache_dir / 'tenant' / 'active-workload-identities.json'))
        id_cache.update(load_cache_file(cache_dir / 'policies' / 'groups.json'))
        id_cache.update(load_cache_file(cache_dir / 'policies' / 'roles.json'))
        id_cache.update(load_cache_file(cache_dir / 'policies' / 'service-principals.json'))
        id_cache.update(load_cache_file(cache_dir / 'policies' / 'auth-contexts.json'))
        
        # Load application cache (indexed by both id and appId for flexible lookup)
        app_cache = load_app_cache_file(cache_dir / 'policies' / 'applications.json')
        
        if progress_callback:
            progress_callback(91, f"✓ Loaded {len(id_cache):,} objects and {len(app_cache):,} apps from cache")
        
        # Count unique identities affected by gaps
        unique_identities = set()
        for result in results:
            perm = result.get('permutation', {})
            # Check all identity dimensions
            for identity_key in ['users', 'guests', 'agents', 'workloadIdentities']:
                if identity_key in perm:
                    identity_value = perm[identity_key]
                    # Handle both dict format (with 'id' key) and string format
                    if isinstance(identity_value, dict):
                        unique_identities.add(identity_value.get('id', identity_value))
                    else:
                        unique_identities.add(identity_value)
                    break
        
        # Build JSON report
        identity_count_msg = f" affecting {len(unique_identities):,} identities" if unique_identities else ""
        msg = f"Resolving IDs in identified gaps (0% completed)"
        if progress_callback:
            progress_callback(93, msg)
        else:
            print(f"Building JSON report for {len(results):,} gaps{identity_count_msg} ...")
            print(msg)
        
        enhanced_results = []
        total_results = len(results)
        last_reported_pct = 0
        
        for idx, result in enumerate(results):
            lineage = result.get('lineage', '')
            is_gap = not result.get('terminated', False)
            
            # Extract component IDs from permutation dict
            perm_dict = result.get('permutation', {})
            components = {}
            for key, value in perm_dict.items():
                if isinstance(value, dict):
                    # Extract ID from dict format
                    components[key] = value.get('id', value)
                else:
                    components[key] = value
            
            # Resolve IDs to display names using cache
            resolved_permutation = {}
            
            # Get original permutation dict to preserve extra fields like 'count'
            original_perm = result.get('permutation', {})
            
            for key, value in components.items():
                if key in ['users', 'guests', 'agents', 'workloadIdentities']:
                    # Check if we have the full dict from original permutation
                    original_dict = original_perm.get(key, {}) if isinstance(original_perm.get(key), dict) else {}
                    
                    # Determine the correct type label based on the dimension
                    if key == 'guests':
                        obj_type = original_dict.get('type', 'guest')
                    elif key == 'agents':
                        obj_type = original_dict.get('type', 'agent_identity')
                    elif key == 'workloadIdentities':
                        obj_type = original_dict.get('type', 'workload_identity')
                    else:
                        # For users dimension, check if it's a role, group, or user
                        obj_type = original_dict.get('type')
                        if not obj_type:
                            if self._is_role(value, {}):
                                obj_type = 'role'
                            elif self._is_group(value, {}):
                                obj_type = 'group'
                            else:
                                obj_type = 'user'
                    
                    # Use cache only
                    # Prefer displayName from original dict (critical gap), otherwise resolve from cache
                    resolved = original_dict.get('displayName') or id_cache.get(value, value)
                    perm_obj = {
                        'id': value,
                        'displayName': resolved,
                        'type': obj_type
                    }
                    
                    # Preserve count field if present (critical gap scenario)
                    if 'count' in original_dict:
                        perm_obj['count'] = original_dict['count']
                    
                    # Add user count for groups (including nested groups)
                    if obj_type == 'group' and 'count' not in perm_obj:
                        # Load group memberships
                        group_memberships_file = Path('cache') / 'group_memberships.json'
                        if group_memberships_file.exists():
                            try:
                                with open(group_memberships_file, 'r') as f:
                                    group_memberships = json.load(f)
                                user_count = self._count_group_users(value, group_memberships)
                                perm_obj['userCount'] = user_count
                            except Exception:
                                pass
                    
                    resolved_permutation[key] = perm_obj
                elif key in ['resourceApps', 'userActions', 'agentResources']:
                    # Check if we have the full dict from original permutation
                    original_dict = original_perm.get(key, {}) if isinstance(original_perm.get(key), dict) else {}
                    
                    # Resource dimensions
                    if key == 'resourceApps':
                        # Use cache only
                        # Prefer displayName from original dict (critical gap), otherwise resolve from cache
                        resolved = original_dict.get('displayName') or app_cache.get(value, value)
                        perm_obj = {
                            'id': value,
                            'displayName': resolved
                        }
                        # Preserve count field if present
                        if 'count' in original_dict:
                            perm_obj['count'] = original_dict['count']
                        resolved_permutation[key] = perm_obj
                    else:
                        # userActions and agent_resources can be simple strings or dicts
                        if isinstance(original_dict, dict) and original_dict:
                            perm_obj = {
                                'id': value,
                                'displayName': original_dict.get('displayName', value)
                            }
                            if 'count' in original_dict:
                                perm_obj['count'] = original_dict['count']
                            resolved_permutation[key] = perm_obj
                        else:
                            resolved_permutation[key] = value
                elif key == 'locations':
                    # Check if we have the full dict from original permutation
                    original_dict = original_perm.get(key, {}) if isinstance(original_perm.get(key), dict) else {}
                    
                    # Prefer displayName from original dict (critical gap), otherwise resolve
                    resolved = original_dict.get('displayName') or loc_lookup.get(value) or id_cache.get(value, value)
                    perm_obj = {
                        'id': value,
                        'displayName': resolved
                    }
                    # Preserve count field if present
                    if 'count' in original_dict:
                        perm_obj['count'] = original_dict['count']
                    resolved_permutation[key] = perm_obj
                elif key == 'clientAppTypes':
                    # Check if we have the full dict from original permutation
                    original_dict = original_perm.get(key, {}) if isinstance(original_perm.get(key), dict) else {}
                    
                    if isinstance(original_dict, dict) and original_dict:
                        perm_obj = {
                            'id': value,
                            'displayName': original_dict.get('displayName', value)
                        }
                        if 'count' in original_dict:
                            perm_obj['count'] = original_dict['count']
                        resolved_permutation[key] = perm_obj
                    else:
                        # For clientAppTypes, just use the value
                        resolved_permutation[key] = value
                # Handle flat format keys (singular forms used by permutation generator)
                elif key == 'location':
                    # Resolve location ID to display name
                    resolved = loc_lookup.get(value) or id_cache.get(value, value)
                    resolved_permutation[key] = resolved
                elif key == 'application':
                    # Resolve application ID to display name
                    resolved = app_cache.get(value, value)
                    resolved_permutation[key] = resolved
                elif key == 'userAction':
                    # Resolve user action ID to display name (strip urn: prefix if present)
                    action_value = value.replace('urn:user:', '') if isinstance(value, str) else value
                    resolved_permutation[key] = action_value
                elif key in ['user', 'guests', 'agent', 'workload']:
                    # Resolve identity ID to display name
                    resolved = id_cache.get(value, value)
                    resolved_permutation[key] = resolved
                else:
                    # For platforms and other dimensions, just use the value
                    resolved_permutation[key] = value
            
            # Build simplified result (gaps only - no control analysis)
            enhanced_result = {
                'permutation': resolved_permutation,
                'lineage': lineage,
                'terminated': not is_gap
            }
            
            # Preserve is_critical and gap_type flags from analysis
            if 'is_critical' in result:
                enhanced_result['is_critical'] = result['is_critical']
            if 'gap_type' in result:
                enhanced_result['gap_type'] = result['gap_type']
            if 'is_universal_gap' in result:
                enhanced_result['is_universal_gap'] = result['is_universal_gap']
            
            if 'gap_source' in result:
                enhanced_result['gap_source'] = {
                    'id': result['gap_source'],
                    'displayName': id_cache.get(result['gap_source'], result['gap_source']),
                    'type': result.get('gap_source_type', 'unknown')
                }
            
            enhanced_results.append(enhanced_result)
            
            # Report progress every 10% for web interface (scale from 93% to 97%)
            if progress_callback:
                completed_pct = int(((idx + 1) / total_results) * 100)
                # Map internal progress (0-100%) to external progress range (93-97%)
                overall_pct = 93 + int(completed_pct * 0.04)  # Scale to 4% range
                # Report every 1% increment
                if overall_pct > last_reported_pct:
                    progress_callback(overall_pct, f"Resolving IDs in identified gaps ({completed_pct}% completed)")
                    last_reported_pct = overall_pct
        
        # Fetch primary domain for metadata
        primary_domain = None
        if self.api_client and self.token:
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                response = requests.get(
                    'https://graph.microsoft.com/v1.0/organization',
                    headers=headers,
                    timeout=10
                )
                if response.ok:
                    data = response.json()
                    if data.get('value') and len(data['value']) > 0:
                        org = data['value'][0]
                        verified_domains = org.get('verifiedDomains', [])
                        # Find the primary or initial domain
                        for domain in verified_domains:
                            if domain.get('isInitial') or domain.get('isDefault'):
                                primary_domain = domain.get('name')
                                break
            except Exception as e:
                # Non-critical - continue without domain
                pass
        
        # Prepare JSON data
        metadata = {
            'generatedAt': datetime.now().isoformat(),
            'tenantId': self.tenant_id,
            'primaryDomain': primary_domain,
            'totalPermutations': len(results),
            'gaps': len([r for r in results if not r.get('terminated')]),
            'version': '2.0',
            'excludedPoliciesCount': len(excluded_policies or [])
        }
        
        # Add analysis timestamps if provided
        if analysis_start_time is not None:
            metadata['analysisStartTime'] = datetime.fromtimestamp(analysis_start_time).isoformat()
        if analysis_end_time is not None:
            metadata['analysisEndTime'] = datetime.fromtimestamp(analysis_end_time).isoformat()
        if analysis_start_time is not None and analysis_end_time is not None:
            metadata['analysisDurationSeconds'] = round(analysis_end_time - analysis_start_time, 2)
        
        # Add universal coverage stats if provided
        if universal_coverage_stats:
            metadata['universalCoverage'] = universal_coverage_stats
        
        # Add filter statistics if provided
        if filter_statistics:
            metadata['filterStatistics'] = {
                'totalIdentitiesInTenant': filter_statistics.get('total_identities_in_tenant', 0),
                'includedUsersCount': filter_statistics.get('included_users_count', 0),
                'excludedUsersCount': filter_statistics.get('excluded_users_count', 0)
            }
        
        json_data = {
            'metadata': metadata,
            'results': enhanced_results,
            'excludedPolicies': excluded_policies or []
        }
        
        # Calculate size in human-readable format
        json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
        size_bytes = len(json_str.encode('utf-8'))
        
        # Convert to human-readable size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                size_str = f"{size_bytes:.2f} {unit}"
                break
            size_bytes /= 1024.0
        
        # Report before writing
        write_msg = f"Writing JSON report ({size_str})..."
        if progress_callback:
            progress_callback(98, write_msg)
        else:
            print(write_msg)
        
        # Write JSON
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(json_str)
        
        completion_msg = f"✓ JSON report written to {filename}"
        if progress_callback:
            progress_callback(100, completion_msg)
        else:
            print(completion_msg)
        return filename
    
    def generate_portal_with_policy_browser(self, policies: List[Dict], named_locations: List[Dict] = None, mapper = None) -> str:
        """Generate portal.html with embedded policy browser content.
        
        Creates a copy of the portal.html template and injects the policy browser HTML.
        Always saves to the root directory (portal.html) - the portal GUI can load JSON files
        from the organized folder structure.
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects
            named_locations (List[Dict], optional): List of named location objects
            mapper (UserMapper, optional): Mapper with cached object ID resolutions
        
        Returns:
            str: Path to the generated portal.html file
        """
        # Read the portal template
        template_path = Path(__file__).parent.parent.parent / 'templates' / 'portal-template.html'
        
        # Always save to root directory - single portal for all JSON files
        output_path = Path.cwd() / 'portal.html'
        
        # Generate policy browser HTML with resolved IDs
        policy_browser_html = self.generate_policy_browser_html(policies, named_locations, mapper)
        
        # Read template
        with open(template_path, 'r', encoding='utf-8') as f:
            portal_content = f.read()
        
        # Inject policy browser HTML into the policyBrowserContent div
        portal_content = portal_content.replace(
            '<div id="policyBrowserContent"></div>',
            f'<div id="policyBrowserContent">{policy_browser_html}</div>'
        )
        
        # Write the portal file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(portal_content)

        # Report progress
        if self.progress_callback:
            self.progress_callback(86, f"✓ Generated policy browser HTML with {len(policies)} policies")

        return str(output_path)
        
    def _generate_filename(self, extension: str) -> str:
        """Generate a filename with folder structure, timestamp, source, assignment, and target resource.
        
        Creates organized folder structure and filename:
        - Folder: cainsight_reports_{tenantId}/{assignment}_reports/
        - Filename: YYYY-MM-DD_HH-MM-SS_cainsight_report_{interface}_{assignment}_{target-resource}.{ext}
        
        Parameters:
            extension (str): File extension without the dot (e.g., 'json')
        
        Returns:
            str: Full path to the generated file with folder structure
        """
        now = datetime.now()
        datetime_str = now.strftime("%Y-%m-%d_%H-%M-%S")
        
        # Build filename components
        filename_parts = [datetime_str, "cainsight_report"]
        
        # Add interface (source)
        if self.source:
            filename_parts.append(self.source)
        
        # Add assignment type
        if self.assignment:
            filename_parts.append(self.assignment)
        
        # Add target resource (with mapping)
        if self.target_resource:
            # Map cloud-apps to cloud-applications for filename
            resource_name = 'cloud-applications' if self.target_resource == 'cloud-apps' else self.target_resource
            filename_parts.append(resource_name)
        
        filename = "_".join(filename_parts) + f".{extension}"
        
        # Build folder structure if we have tenant ID and assignment
        if self.tenant_id and self.assignment:
            # Create root folder: cainsight_reports_{tenantId}
            root_folder = Path.cwd() / f"cainsight_reports_{self.tenant_id}"
            
            # Create assignment subfolder: {assignment}_reports
            output_folder = root_folder / f"{self.assignment}_reports"
            
            # Ensure folder exists
            output_folder.mkdir(parents=True, exist_ok=True)
            
            # Return full path
            return str(output_folder / filename)
        else:
            # Fallback to old behavior if missing tenant ID or assignment
            if self.tenant_id:
                filename = f"{datetime_str}_cainsight_report"
                if self.source:
                    filename += f"_{self.source}"
                filename += f"_{self.tenant_id}.{extension}"
            return filename
        
    def _is_group(self, obj_id: str, id_cache: Dict[str, str]) -> bool:
        """Check if an object ID represents a group.
        
        Queries the groups.json cache file to determine if an object is a group.
        
        Parameters:
            obj_id (str): Directory object ID to check
            id_cache (Dict[str, str]): Cache dictionary (not used in current implementation)
        
        Returns:
            bool: True if the object is a group, False otherwise
        """
        groups_file = Path('cache') / 'policies' / 'groups.json'
        if groups_file.exists():
            try:
                with open(groups_file, 'r') as f:
                    groups = json.load(f)
                    return any(group.get('id') == obj_id for group in groups)
            except Exception:
                pass
        return False
    
    def _count_group_users(self, group_id: str, group_memberships: List[str], visited: set = None) -> int:
        """Recursively count total unique users in a group including nested groups.
        
        Parameters:
            group_id (str): Group ID to count users for
            group_memberships (List[str]): List of membership links in format 'groupId:memberId'
            visited (set): Set of already visited group IDs to prevent infinite loops
        
        Returns:
            int: Total count of unique users in the group and all nested groups
        """
        if visited is None:
            visited = set()
        
        # Prevent infinite recursion on circular group memberships
        if group_id in visited:
            return 0
        visited.add(group_id)
        
        unique_users = set()
        
        # Find all direct members of this group
        for link in group_memberships:
            if ':' in link:
                gid, member_id = link.split(':', 1)
                if gid == group_id:
                    # Check if this member is a group or a user
                    if self._is_group(member_id, {}):
                        # Recursively count users in nested group
                        nested_users_count = self._count_group_users(member_id, group_memberships, visited)
                        # We need to get the actual user IDs from nested groups
                        # For simplicity, we'll use a different approach - get all transitive members
                        nested_members = self._get_all_group_members(member_id, group_memberships, visited.copy())
                        unique_users.update(nested_members)
                    else:
                        # This is a user, add to set
                        unique_users.add(member_id)
        
        return len(unique_users)
    
    def _get_all_group_members(self, group_id: str, group_memberships: List[str], visited: set = None) -> set:
        """Recursively get all user member IDs in a group including nested groups.
        
        Parameters:
            group_id (str): Group ID to get members for
            group_memberships (List[str]): List of membership links in format 'groupId:memberId'
            visited (set): Set of already visited group IDs to prevent infinite loops
        
        Returns:
            set: Set of all user IDs that are members (directly or through nested groups)
        """
        if visited is None:
            visited = set()
        
        if group_id in visited:
            return set()
        visited.add(group_id)
        
        all_members = set()
        
        # Find all direct members
        for link in group_memberships:
            if ':' in link:
                gid, member_id = link.split(':', 1)
                if gid == group_id:
                    if self._is_group(member_id, {}):
                        # Recursively get members from nested group
                        nested_members = self._get_all_group_members(member_id, group_memberships, visited)
                        all_members.update(nested_members)
                    else:
                        # This is a user
                        all_members.add(member_id)
        
        return all_members
    
    def _is_role(self, obj_id: str, id_cache: Dict[str, str]) -> bool:
        """Check if an object ID represents a directory role.
        
        Queries the roles.json cache file to determine if an object is an Entra role.
        
        Parameters:
            obj_id (str): Directory object ID to check
            id_cache (Dict[str, str]): Cache dictionary (not used in current implementation)
        
        Returns:
            bool: True if the object is a directory role, False otherwise
        """
        roles_file = Path('cache') / 'policies' / 'roles.json'
        if roles_file.exists():
            try:
                with open(roles_file, 'r') as f:
                    roles = json.load(f)
                    return any(role.get('id') == obj_id for role in roles)
            except Exception:
                pass
        return False
    
    def _resolve_application(self, app_id: str, app_cache: Dict[str, str]) -> str:
        """Resolve an application ID to its display name.
        
        Uses cache only - checks in-memory cache first, then applications.json file.
        Returns the original app ID if not found in cache. Does NOT make API calls
        since this runs late in the workflow when the token may be expired.
        
        Parameters:
            app_id (str): Application ID (appId, not object ID) to resolve
            app_cache (Dict[str, str]): Cache dictionary mapping app IDs to display names
        
        Returns:
            str: Application display name or original app ID if not found in cache
        """
        # Check cache first
        if app_id in app_cache:
            return app_cache[app_id]
        
        # Check applications file
        applications_file = Path('cache') / 'policies' / 'applications.json'
        if applications_file.exists():
            try:
                with open(applications_file, 'r') as f:
                    apps = json.load(f)
                    for app in apps:
                        if app.get('appId') == app_id:
                            display_name = app.get('displayName', app_id)
                            app_cache[app_id] = display_name
                            return display_name
            except Exception:
                pass
        
        # Return original ID if not found in cache
        # NOTE: No API fallback - token may be expired at this stage
        app_cache[app_id] = app_id
        return app_id
    
    def _parse_lineage(self, lineage: str) -> Dict[str, str]:
        """Parse lineage string into component dictionary.
        
        Converts a lineage path string into a dictionary mapping condition types to values.
        
        Parameters:
            lineage (str): Lineage string in format 'type:value -> type:value -> ...'
                          (e.g., 'users:Alice -> resourceApps:Word -> ')
        
        Returns:
            Dict[str, str]: Dictionary mapping condition types to values
                           (e.g., {'users': 'Alice', 'resourceApps': 'Word'})
        """
        components = {}
        parts = [p.strip() for p in lineage.split('->') if p.strip()]
        
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                components[key] = value
                
        return components
    
    def generate_policy_browser_html(self, policies: List[Dict], named_locations: List[Dict] = None, mapper = None) -> str:
        """Generate HTML content for the policy browser.
        
        Creates a formatted HTML string displaying all conditional access policies
        with filtering capabilities. Resolves object IDs to display names using
        cached data from mapper (users, groups, roles, applications).
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects from Graph API
            named_locations (List[Dict], optional): List of named location objects for
                                                   ID resolution. Default is None.
            mapper (UserMapper, optional): Mapper with cached object ID resolutions.
                                          Default is None.
        
        Returns:
            str: HTML content for the policy browser
        """
        # Build ID cache from mapper's cached files
        id_cache = {}
        
        # Load cached mappings from mapper if available
        if mapper:
            # Load users
            users = mapper.load_users()
            for user in users:
                user_id = user.get('id')
                display_name = user.get('displayName') or user.get('userPrincipalName') or user_id
                if user_id:
                    id_cache[user_id] = display_name
            
            # Load groups
            groups = mapper.load_groups()
            for group in groups:
                group_id = group.get('id')
                display_name = group.get('displayName') or group_id
                if group_id:
                    id_cache[group_id] = display_name
            
            # Load roles
            roles = mapper.load_roles()
            for role in roles:
                role_id = role.get('id')
                display_name = role.get('displayName') or role_id
                if role_id:
                    id_cache[role_id] = display_name
            
            # Load applications
            applications = mapper.load_applications()
            for app in applications:
                app_id = app.get('appId')
                display_name = app.get('displayName') or app_id
                if app_id:
                    id_cache[app_id] = display_name
            
            # Load service principals
            service_principals = mapper.load_service_principals()
            for sp in service_principals:
                sp_id = sp.get('id')
                display_name = sp.get('displayName') or sp_id
                if sp_id:
                    id_cache[sp_id] = display_name
            
            # Load authentication contexts
            auth_contexts = mapper.load_auth_contexts()
            for ctx in auth_contexts:
                ctx_id = ctx.get('id')
                display_name = ctx.get('displayName') or ctx_id
                if ctx_id:
                    id_cache[ctx_id] = display_name
        else:
            # Fallback: Load from cache files directly if no mapper provided
            users_file = Path('cache') / 'policies' / 'users.json'
            if users_file.exists():
                with open(users_file, 'r') as f:
                    users = json.load(f)
                    for user in users:
                        user_id = user.get('id')
                        name = user.get('displayName') or user.get('userPrincipalName') or user_id
                        if user_id:
                            id_cache[user_id] = name
            
            # Load groups
            groups_file = Path('cache') / 'policies' / 'groups.json'
            if groups_file.exists():
                with open(groups_file, 'r') as f:
                    groups = json.load(f)
                    for group in groups:
                        group_id = group.get('id')
                        name = group.get('displayName') or group_id
                        if group_id:
                            id_cache[group_id] = name
            
            # Load roles
            roles_file = Path('cache') / 'policies' / 'roles.json'
            if roles_file.exists():
                with open(roles_file, 'r') as f:
                    roles = json.load(f)
                    for role in roles:
                        role_id = role.get('id')
                        name = role.get('displayName') or role_id
                        if role_id:
                            id_cache[role_id] = name
            
            # Load applications
            applications_file = Path('cache') / 'policies' / 'applications.json'
            if applications_file.exists():
                with open(applications_file, 'r') as f:
                    apps = json.load(f)
                    for app in apps:
                        app_id = app.get('appId')
                        name = app.get('displayName') or app_id
                        if app_id:
                            id_cache[app_id] = name
            
            # Load service principals
            service_principals_file = Path('cache') / 'policies' / 'service-principals.json'
            if service_principals_file.exists():
                with open(service_principals_file, 'r') as f:
                    sps = json.load(f)
                    for sp in sps:
                        sp_id = sp.get('id')
                        name = sp.get('displayName') or sp_id
                        if sp_id:
                            id_cache[sp_id] = name
            
            # Load authentication contexts
            auth_contexts_file = Path('cache') / 'policies' / 'auth-contexts.json'
            if auth_contexts_file.exists():
                with open(auth_contexts_file, 'r') as f:
                    contexts = json.load(f)
                    for ctx in contexts:
                        ctx_id = ctx.get('id')
                        name = ctx.get('displayName') or ctx_id
                        if ctx_id:
                            id_cache[ctx_id] = name
        
        # Build location lookup
        loc_lookup = {loc.get('id'): loc.get('displayName', loc.get('id')) for loc in (named_locations or [])}
        id_cache.update(loc_lookup)
        
        # Add special CA values to cache so they map to themselves
        for special_value in SPECIAL_CA_VALUES:
            id_cache[special_value] = special_value
        
        # Resolve IDs in policies to display names (from cache)
        for policy in policies:
            cond = policy.get('conditions') or {}
            users = cond.get('users') or {}
            apps = cond.get('applications') or {}
            locations = cond.get('locations') or {}
            client_apps = cond.get('clientApplications') or {}
            
            # Resolve user/group/role IDs using cached data
            users['includeUsers'] = self._resolve_list(users.get('includeUsers'), id_cache, loc_lookup)
            users['excludeUsers'] = self._resolve_list(users.get('excludeUsers'), id_cache, loc_lookup)
            users['includeGroups'] = self._resolve_list(users.get('includeGroups'), id_cache, loc_lookup)
            users['excludeGroups'] = self._resolve_list(users.get('excludeGroups'), id_cache, loc_lookup)
            users['includeRoles'] = self._resolve_list(users.get('includeRoles'), id_cache, loc_lookup)
            users['excludeRoles'] = self._resolve_list(users.get('excludeRoles'), id_cache, loc_lookup)
            
            # Resolve application IDs
            apps['includeApplications'] = self._resolve_list(apps.get('includeApplications'), id_cache, loc_lookup)
            apps['excludeApplications'] = self._resolve_list(apps.get('excludeApplications'), id_cache, loc_lookup)
            
            # Resolve authentication context IDs
            if apps.get('includeAuthenticationContextClassReferences'):
                apps['includeAuthenticationContextClassReferences'] = self._resolve_list(
                    apps.get('includeAuthenticationContextClassReferences'), id_cache, loc_lookup
                )
            
            # Strip "urn:user:" prefix from user actions
            if apps.get('includeUserActions'):
                apps['includeUserActions'] = [
                    action.replace('urn:user:', '') if isinstance(action, str) else action
                    for action in apps['includeUserActions']
                ]
            
            # Resolve location IDs
            locations['includeLocations'] = self._resolve_list(locations.get('includeLocations'), id_cache, loc_lookup)
            locations['excludeLocations'] = self._resolve_list(locations.get('excludeLocations'), id_cache, loc_lookup)
            
            # Resolve service principal IDs
            if client_apps:
                client_apps['includeServicePrincipals'] = self._resolve_list(client_apps.get('includeServicePrincipals'), id_cache, loc_lookup)
                client_apps['excludeServicePrincipals'] = self._resolve_list(client_apps.get('excludeServicePrincipals'), id_cache, loc_lookup)
            
            # Update policy with resolved names
            cond['users'] = users
            cond['applications'] = apps
            cond['locations'] = locations
            if client_apps:
                cond['clientApplications'] = client_apps
            policy['conditions'] = cond
            
            # Normalize Sign-in Frequency session control values
            session_controls = policy.get('sessionControls', {}) or {}
            if session_controls.get('signInFrequency'):
                freq = session_controls['signInFrequency']
                
                # Replace "None None" with "Every time"
                value = freq.get('value', '')
                freq_type = freq.get('type', '')
                if not value and not freq_type:
                    freq['value'] = 'Every time'
                    freq['type'] = ''
                
                # Remove "(primaryAndSecondaryAuthentication)" from authenticationType
                auth_type = freq.get('authenticationType', '')
                if auth_type:
                    freq['authenticationType'] = auth_type.replace('primaryAndSecondaryAuthentication', '').strip('()')
        
        # Sort policies alphabetically
        policies.sort(key=lambda p: (p.get('displayName') or '').lower())
        
        # Generate HTML
        html_parts = []
        html_parts.append('''
        <style>
            #policyBrowserContent {
                position: relative;
                z-index: auto;
            }
            #policyCardsContainer {
                position: relative;
                z-index: 1;
            }
            .multi-select-dropdown {
                position: relative;
                display: inline-block;
                min-width: 200px;
                z-index: 1000;
            }
            .multi-select-dropdown.open {
                z-index: 15000;
            }
            .multi-select-button {
                padding: 10px 35px 10px 12px;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                background: white;
                cursor: pointer;
                font-size: 14px;
                text-align: left;
                width: 100%;
                position: relative;
                transition: all 0.2s;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .multi-select-button:hover {
                border-color: #667eea;
                background: #f8f9ff;
            }
            .multi-select-button.active {
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .multi-select-button::after {
                content: '▼';
                position: absolute;
                right: 12px;
                top: 50%;
                transform: translateY(-50%);
                font-size: 10px;
                color: #666;
                transition: transform 0.2s;
            }
            .multi-select-button.active::after {
                transform: translateY(-50%) rotate(180deg);
            }
            .multi-select-count {
                background: #667eea;
                color: white;
                border-radius: 10px;
                padding: 2px 8px;
                font-size: 12px;
                font-weight: 600;
                margin-left: 8px;
            }
            .multi-select-options {
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                margin-top: 4px;
                background: white;
                border: 2px solid #667eea;
                border-radius: 6px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                max-height: 300px;
                overflow-y: auto;
                z-index: 10000;
                display: none;
            }
            .multi-select-options.show {
                display: block;
            }
            .multi-select-option {
                padding: 10px 12px;
                cursor: pointer;
                transition: background 0.15s;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .multi-select-option:hover {
                background: #f8f9ff;
            }
            .multi-select-option input[type="checkbox"] {
                width: 16px;
                height: 16px;
                cursor: pointer;
                accent-color: #667eea;
            }
            .multi-select-option label {
                cursor: pointer;
                flex: 1;
                font-size: 14px;
                color: #333;
            }
            /* Click-to-copy ID styling */
            .id-container {
                position: relative;
                display: inline-block;
                padding-right: 0;
                transition: padding-right 0.2s;
            }
            .id-container:hover {
                padding-right: 20px;
            }
            .copy-id-btn {
                position: absolute;
                top: 50%;
                right: 0;
                transform: translateY(-50%);
                display: flex;
                align-items: center;
                justify-content: center;
                width: 16px;
                height: 16px;
                padding: 0;
                background: #667eea;
                border: none;
                border-radius: 3px;
                cursor: pointer;
                opacity: 0;
                transition: opacity 0.2s, background 0.2s;
            }
            .id-container:hover .copy-id-btn {
                opacity: 0.8;
            }
            .copy-id-btn:hover {
                opacity: 1 !important;
                background: #5568d3;
            }
            .copy-id-btn:active {
                transform: scale(0.95);
            }
            .copy-id-btn svg {
                width: 10px;
                height: 10px;
                fill: white;
            }
            .copy-feedback {
                position: absolute;
                top: -25px;
                left: 50%;
                transform: translateX(-50%);
                background: #2d3748;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                white-space: nowrap;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s;
                z-index: 1000;
            }
            .copy-feedback.show {
                opacity: 1;
            }
            /* Search bar styling */
            .search-container {
                margin-bottom: 20px;
            }
            .search-input {
                width: 100%;
                padding: 12px 16px 12px 40px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 15px;
                transition: all 0.2s;
                background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="%23666" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>');
                background-repeat: no-repeat;
                background-position: 12px center;
                background-size: 18px;
            }
            .search-input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .search-input::placeholder {
                color: #999;
            }
            /* Toggle switch styling */
            .toggle-switch {
                position: relative;
                display: inline-block;
                width: 48px;
                height: 24px;
            }
            .toggle-switch input {
                opacity: 0;
                width: 0;
                height: 0;
            }
            .toggle-slider {
                position: absolute;
                cursor: pointer;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-color: #ccc;
                transition: 0.3s;
                border-radius: 24px;
            }
            .toggle-slider:before {
                position: absolute;
                content: "";
                height: 18px;
                width: 18px;
                left: 3px;
                bottom: 3px;
                background-color: white;
                transition: 0.3s;
                border-radius: 50%;
            }
            input:checked + .toggle-slider {
                background-color: #667eea;
            }
            input:checked + .toggle-slider:before {
                transform: translateX(24px);
            }
            /* Search bar styling */
            .search-container {
                margin-bottom: 20px;
            }
            .search-input {
                width: 100%;
                padding: 12px 16px 12px 40px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 15px;
                transition: all 0.2s;
                background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="%23666" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>');
                background-repeat: no-repeat;
                background-position: 12px center;
                background-size: 18px;
            }
            .search-input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .search-input::placeholder {
                color: #999;
            }
            /* Search highlight styling */
            .search-highlight {
                background-color: #ffeb3b;
                color: #000;
                padding: 2px 0;
                border-radius: 2px;
                font-weight: 500;
            }
            /* Reset button styling */
            .reset-filters-btn {
                padding: 10px 20px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s;
            }
            .reset-filters-btn:hover {
                background: #5568d3;
            }
            .reset-filters-btn:active {
                transform: scale(0.98);
            }
            
            /* Glassmorphism Design Styles */
            .glassmorphism-container {
                background: linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(102, 126, 234, 0.15);
                border-radius: 20px;
                padding: 25px;
                width: 100%;
                box-sizing: border-box;
                overflow: visible;
                position: relative;
                z-index: 100;
            }
            
            .glassmorphism-container.open {
                z-index: 15002;
            }
            
            .policy-state-glass {
                background: rgba(255, 255, 255, 0.4);
                backdrop-filter: blur(15px);
                padding: 18px;
                border-radius: 12px;
                margin-bottom: 25px;
                border: 1px solid rgba(255, 255, 255, 0.5);
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 20px;
            }
            
            .policy-state-left {
                display: flex;
                flex-direction: column;
            }
            
            .policy-state-glass label {
                font-size: 13px;
                font-weight: 600;
                color: #444;
                display: block;
                margin-bottom: 8px;
                text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
            }
            
            .policy-state-glass select {
                padding: 10px 12px;
                border: 2px solid rgba(102, 126, 234, 0.2);
                border-radius: 8px;
                font-size: 14px;
                min-width: 160px;
                cursor: pointer;
                background: rgba(255, 255, 255, 0.6);
                backdrop-filter: blur(5px);
                transition: all 0.2s;
            }
            
            .policy-state-glass select:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            
            .policy-count-text {
                font-size: 14px;
                color: #555;
                font-weight: 600;
                text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
                white-space: nowrap;
            }
            
            .filters-collapse-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 12px 18px;
                background: rgba(255, 255, 255, 0.5);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                margin-bottom: 20px;
                cursor: pointer;
                transition: all 0.3s;
                border: 1px solid rgba(102, 126, 234, 0.2);
            }
            
            .filters-collapse-header:hover {
                background: rgba(255, 255, 255, 0.7);
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.08);
            }
            
            .filters-collapse-title {
                font-size: 16px;
                font-weight: 700;
                color: #667eea;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .filters-collapse-icon {
                font-size: 20px;
                transition: transform 0.3s;
            }
            
            .filters-collapse-icon.collapsed {
                transform: rotate(-90deg);
            }
            
            .filters-collapsible-content {
                max-height: 2000px;
                overflow: visible;
                transition: max-height 0.3s ease-out, opacity 0.3s;
                opacity: 1;
            }
            
            .filters-collapsible-content.collapsed {
                max-height: 0;
                opacity: 0;
                overflow: hidden;
            }
            
            .policy-count-section {
                background: rgba(255, 255, 255, 0.6);
                backdrop-filter: blur(10px);
                padding: 12px 18px;
                border-radius: 10px;
                margin: 20px 0;
                text-align: left;
                border: 1px solid rgba(102, 126, 234, 0.15);
                position: relative;
                z-index: 1;
            }
            
            .policy-count-section.open {
                z-index: 15001;
            }
            
            .categories-glass-grid {
                display: grid;
                grid-template-columns: 1fr;
                gap: 18px;
            }
            
            .category-glass-card {
                background: rgba(255, 255, 255, 0.25);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.4);
                border-radius: 16px;
                padding: 20px;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
                position: relative;
                z-index: 1;
                display: flex;
                gap: 20px;
                align-items: flex-start;
            }
            
            .category-glass-card.open {
                z-index: 15001;
            }
            
            .category-glass-card:hover {
                background: rgba(255, 255, 255, 0.35);
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            }
            
            .category-glass-header {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 8px;
                min-width: 100px;
                flex-shrink: 0;
            }
            
            .category-glass-icon {
                width: 42px;
                height: 42px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 22px;
                background: rgba(255, 255, 255, 0.3);
                backdrop-filter: blur(10px);
                border: 2px solid rgba(255, 255, 255, 0.5);
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
            }
            
            .category-glass-title {
                font-size: 14px;
                font-weight: 700;
                color: #333;
                text-shadow: 0 1px 3px rgba(255, 255, 255, 0.8);
                letter-spacing: 0.3px;
                text-align: center;
            }
            
            .filters-glass-list {
                display: flex;
                flex-direction: column;
                gap: 10px;
                flex: 1;
            }
            
            .filters-glass-grid-2col {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
                flex: 1;
            }
            
            .filters-glass-grid-3col {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                flex: 1;
            }
            
            @media (max-width: 1100px) {
                .filters-glass-grid-3col {
                    grid-template-columns: repeat(2, 1fr);
                }
            }
            
            @media (max-width: 900px) {
                .filters-glass-grid-2col, .filters-glass-grid-3col {
                    grid-template-columns: 1fr;
                    gap: 10px;
                }
                
                .category-glass-card {
                    flex-direction: column;
                    gap: 15px;
                }
                
                .category-glass-header {
                    flex-direction: row;
                    gap: 12px;
                    min-width: unset;
                }
                
                .category-glass-icon {
                    width: 36px;
                    height: 36px;
                    font-size: 18px;
                }
                
                .category-glass-title {
                    font-size: 15px;
                    text-align: left;
                    align-self: center;
                }
            }
            
            .filter-glass-item {
                background: rgba(255, 255, 255, 0.25);
                padding: 10px;
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 0.3);
                transition: all 0.2s;
            }
            
            .filter-glass-item:hover {
                background: rgba(255, 255, 255, 0.4);
            }
            
            .filter-glass-item label {
                font-size: 11px;
                font-weight: 600;
                color: #555;
                display: block;
                margin-bottom: 6px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .filter-glass-item .multi-select-button {
                background: rgba(255, 255, 255, 0.4);
                backdrop-filter: blur(5px);
                border: 1px solid rgba(102, 126, 234, 0.2);
                font-size: 13px;
                padding: 9px 32px 9px 10px;
            }
            
            .filter-glass-item .multi-select-button:hover {
                background: rgba(255, 255, 255, 0.6);
                border-color: #667eea;
            }
        </style>
        
        <div class="policy-browser-header">
            <div style="margin-bottom: 15px;">
                <h2 style="color: #667eea; font-size: 24px; margin: 0;">🔎 Policy Browser</h2>
                <p style="color: #666; font-size: 14px; margin: 5px 0 0 0;">Browse and filter all conditional access policies</p>
            </div>
            
            <!-- Search bar with Refresh button on the left -->
            <div id="policySearchRow" style="display: flex; gap: 10px; align-items: center; margin-bottom: 20px;">
                <div class="search-container" style="flex: 1; margin-bottom: 0;">
                    <input type="text" id="policySearch" class="search-input" placeholder="Search policies..." oninput="filterPolicies()">
                </div>
                <button onclick="refreshPolicyBrowser()" style="padding: 9px 16px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; white-space: nowrap;" onmouseover="this.style.background='#5568d3'" onmouseout="this.style.background='#667eea'">
                    ↻ Refresh
                </button>
            </div>
            
            <!-- Policy State dropdown and Toggle - moved to sidebar when loaded -->
            <div id="policyStateRow" style="display: flex; flex-wrap: wrap; gap: 15px; align-items: center; margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 10px; padding: 10px 16px; background: white; border: 2px solid #e0e0e0; border-radius: 6px;">
                    <label style="font-size: 13px; font-weight: 600; color: #444; margin: 0; white-space: nowrap;">Policy State:</label>
                    <select id="policyStateFilter" onchange="filterPolicies()" style="padding: 6px 10px; border: 1px solid #d0d0d0; border-radius: 4px; font-size: 14px; cursor: pointer; background: white; min-width: 140px;">
                        <option value="all">All</option>
                        <option value="enabled" selected>Enabled</option>
                        <option value="disabled">Disabled</option>
                        <option value="enabledForReportingButNotEnforced">Report-Only</option>
                    </select>
                </div>
                <div>
                    <label style="display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 2px solid #e0e0e0; border-radius: 6px; cursor: pointer; background: white; transition: all 0.2s;">
                        <label class="toggle-switch">
                            <input type="checkbox" id="unassignedOnlyFilter" onchange="filterPolicies()">
                            <span class="toggle-slider"></span>
                        </label>
                        <span style="font-size: 14px; color: #333;">Enabled but not applying</span>
                    </label>
                </div>
            </div>
            
            <div id="policyFiltersContainer" class="policy-filter">
                <!-- Glassmorphism Design with Categorized Filters -->
                <div class="glassmorphism-container">
                    
                    <!-- Collapsible Header -->
                    <div class="filters-collapse-header" onclick="toggleFiltersCollapse()">
                        <div class="filters-collapse-title">
                            <span>🔍</span>
                            <span>Filter Options</span>
                        </div>
                        <span id="filtersCollapseIcon" class="filters-collapse-icon">▼</span>
                    </div>
                    
                    <div id="filtersCollapsibleContent" class="filters-collapsible-content">
                    
                    <!-- Three Category Cards -->
                    <div class="categories-glass-grid">
                        
                        <!-- Targets Category -->
                        <div class="category-glass-card">
                            <div class="category-glass-header">
                                <div class="category-glass-icon">🎯</div>
                                <div class="category-glass-title">Targets</div>
                            </div>
                            <div class="filters-glass-grid-2col">
                                <div class="filter-glass-item">
                                    <label>Applies To:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('appliesToFilter')">
                                            <span id="appliesToLabel">Any</span>
                                        </div>
                                        <div id="appliesToFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="agents" onchange="updateFilter('appliesToFilter')"><label>Agents</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="roles" onchange="updateFilter('appliesToFilter')"><label>Directory Roles</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="guests" onchange="updateFilter('appliesToFilter')"><label>Guests and External Users</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="users" onchange="updateFilter('appliesToFilter')"><label>Users and Groups</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="servicePrincipals" onchange="updateFilter('appliesToFilter')"><label>Workload Identities</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Target Resources:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('resourceTypeFilter')">
                                            <span id="resourceTypeLabel">Any</span>
                                        </div>
                                        <div id="resourceTypeFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="agentResources" onchange="updateFilter('resourceTypeFilter')"><label>Agent Resources</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="authContext" onchange="updateFilter('resourceTypeFilter')"><label>Authentication Contexts</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="allApps" onchange="updateFilter('resourceTypeFilter')"><label>Cloud Applications</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="userActions" onchange="updateFilter('resourceTypeFilter')"><label>User Actions</label></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Conditions Category -->
                        <div class="category-glass-card">
                            <div class="category-glass-header">
                                <div class="category-glass-icon">⚙️</div>
                                <div class="category-glass-title">Conditions</div>
                            </div>
                            <div class="filters-glass-grid-3col">
                                <div class="filter-glass-item">
                                    <label>Authentication Flows:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('authFlowFilter')">
                                            <span id="authFlowLabel">Any</span>
                                        </div>
                                        <div id="authFlowFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="authenticationTransfer" onchange="updateFilter('authFlowFilter')"><label>Authentication Transfer</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="deviceCodeFlow" onchange="updateFilter('authFlowFilter')"><label>Device Code</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Client App Types:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('clientAppTypeFilter')">
                                            <span id="clientAppTypeLabel">Any</span>
                                        </div>
                                        <div id="clientAppTypeFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="browser" onchange="updateFilter('clientAppTypeFilter')"><label>Browser</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="exchangeActiveSync" onchange="updateFilter('clientAppTypeFilter')"><label>Exchange ActiveSync</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="mobileDesktop" onchange="updateFilter('clientAppTypeFilter')"><label>Mobile Apps and Desktop</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="otherClients" onchange="updateFilter('clientAppTypeFilter')"><label>Other Clients</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Networks:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('networkFilter')">
                                            <span id="networkLabel">Any</span>
                                        </div>
                                        <div id="networkFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="compliantNetwork" onchange="updateFilter('networkFilter')"><label>Compliant Network</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="trustedLocations" onchange="updateFilter('networkFilter')"><label>Trusted Locations</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Platforms:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('platformFilter')">
                                            <span id="platformLabel">Any</span>
                                        </div>
                                        <div id="platformFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="android" onchange="updateFilter('platformFilter')"><label>Android</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="iOS" onchange="updateFilter('platformFilter')"><label>iOS</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="linux" onchange="updateFilter('platformFilter')"><label>Linux</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="macOS" onchange="updateFilter('platformFilter')"><label>macOS</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="windows" onchange="updateFilter('platformFilter')"><label>Windows</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Risk Levels:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('riskLevelFilter')">
                                            <span id="riskLevelLabel">Any</span>
                                        </div>
                                        <div id="riskLevelFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="servicePrincipalRisk" onchange="updateFilter('riskLevelFilter')"><label>Service Principal Risk</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="signInRisk" onchange="updateFilter('riskLevelFilter')"><label>Sign-in Risk</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="userRisk" onchange="updateFilter('riskLevelFilter')"><label>User Risk</label></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Controls Category -->
                        <div class="category-glass-card">
                            <div class="category-glass-header">
                                <div class="category-glass-icon">🔒</div>
                                <div class="category-glass-title">Controls</div>
                            </div>
                            <div class="filters-glass-grid-2col">
                                <div class="filter-glass-item">
                                    <label>Grant Controls:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('grantControlFilter')">
                                            <span id="grantControlLabel">Any</span>
                                        </div>
                                        <div id="grantControlFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="compliantApplication" onchange="updateFilter('grantControlFilter')"><label>App Protection Policy</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="authStrength" onchange="updateFilter('grantControlFilter')"><label>Authentication Strength</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="block" onchange="updateFilter('grantControlFilter')"><label>Block</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="compliantDevice" onchange="updateFilter('grantControlFilter')"><label>Compliant Device</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="domainJoinedDevice" onchange="updateFilter('grantControlFilter')"><label>Hybrid Joined Device</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="mfa" onchange="updateFilter('grantControlFilter')"><label>Multi-Factor Authentication</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="passwordChange" onchange="updateFilter('grantControlFilter')"><label>Password Change</label></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="filter-glass-item">
                                    <label>Session Controls:</label>
                                    <div class="multi-select-dropdown" style="width: 100%;">
                                        <div class="multi-select-button" onclick="toggleDropdown('sessionControlFilter')">
                                            <span id="sessionControlLabel">Any</span>
                                        </div>
                                        <div id="sessionControlFilter" class="multi-select-options">
                                            <div class="multi-select-option"><input type="checkbox" value="applicationEnforcedRestrictions" onchange="updateFilter('sessionControlFilter')"><label>App Enforced Restrictions</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="cloudAppSecurity" onchange="updateFilter('sessionControlFilter')"><label>Cloud App Security</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="disableResilienceDefaults" onchange="updateFilter('sessionControlFilter')"><label>Disable Resilience</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="persistentBrowser" onchange="updateFilter('sessionControlFilter')"><label>Persistent Browser</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="secureSignInSession" onchange="updateFilter('sessionControlFilter')"><label>Secure Sign-in Session</label></div>
                                            <div class="multi-select-option"><input type="checkbox" value="signInFrequency" onchange="updateFilter('sessionControlFilter')"><label>Sign-in Frequency</label></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                    </div>
                    
                    </div>
                    <!-- End collapsible content -->
                </div>
            </div>
        </div>
        
        <!-- Policy Count Section -->
        <div class="policy-count-section">
            <span id="policyBrowserCount" class="policy-count-text"></span>
        </div>
        
        <div id="policyCardsContainer">
        ''')
        
        for policy in policies:
            state = policy.get('state', 'unknown')
            display_name = policy.get('displayName', 'Unnamed Policy')
            policy_id = policy.get('id', '')
            
            # Extract policy data for filtering
            cond = policy.get('conditions', {}) or {}
            users = cond.get('users', {}) or {}
            apps = cond.get('applications', {}) or {}
            locations = cond.get('locations', {}) or {}
            client_apps = cond.get('clientApplications', {}) or {}
            grant_controls = policy.get('grantControls', {}) or {}
            session_controls = policy.get('sessionControls', {}) or {}
            
            # Check if not applying (unassigned enabled policy)
            include_users = users.get('includeUsers', [])
            is_not_applying = (
                state == 'enabled' and
                include_users and len(include_users) == 1 and include_users[0][0] == 'None' and
                not client_apps
            )
            
            # Collect grant controls
            grant_control_types = []
            built_in_controls = grant_controls.get('builtInControls', []) or []
            grant_control_types.extend(built_in_controls)
            if grant_controls.get('authenticationStrength'):
                grant_control_types.append('authStrength')
            
            # Collect session controls
            session_control_types = []
            if session_controls.get('signInFrequency'):
                session_control_types.append('signInFrequency')
            if session_controls.get('persistentBrowser'):
                session_control_types.append('persistentBrowser')
            if session_controls.get('cloudAppSecurity'):
                session_control_types.append('cloudAppSecurity')
            if session_controls.get('applicationEnforcedRestrictions'):
                session_control_types.append('applicationEnforcedRestrictions')
            if session_controls.get('secureSignInSession'):
                session_control_types.append('secureSignInSession')
            if session_controls.get('disableResilienceDefaults'):
                session_control_types.append('disableResilienceDefaults')
            
            # Determine resource types
            resource_types = []
            include_apps = apps.get('includeApplications', [])
            # Tag policies with agent resources - check tuple's ID field
            if include_apps and any(app_id == 'AllAgentIdResources' for app_id, _ in include_apps):
                resource_types.append('agentResources')
            # Tag policies with cloud applications (either All or individual apps)
            elif include_apps:
                resource_types.append('allApps')
            if apps.get('includeUserActions'):
                resource_types.append('userActions')
            if apps.get('includeAuthenticationContextClassReferences'):
                resource_types.append('authContext')
            
            # Determine applies to types
            applies_to_types = []
            
            # Check for users/groups - exclude policies that ONLY have "None" as user
            include_users_list = users.get('includeUsers', [])
            include_groups_list = users.get('includeGroups', [])
            has_real_users = False
            
            if include_users_list:
                # Filter out 'None' and 'GuestsOrExternalUsers' to see if there are real users
                real_users = [u for u in include_users_list if u[0] not in ['None', 'GuestsOrExternalUsers']]
                if real_users or users.get('excludeUsers'):
                    has_real_users = True
            
            if has_real_users or include_groups_list or users.get('excludeGroups'):
                applies_to_types.append('users')
            
            # Check for guests/external users - check both the dedicated field and the include/exclude users lists
            has_guests = False
            if users.get('includeGuestsOrExternalUsers') or users.get('excludeGuestsOrExternalUsers'):
                has_guests = True
            # Also check if GuestsOrExternalUsers appears in include/exclude users
            if include_users_list and any(u[0] == 'GuestsOrExternalUsers' for u in include_users_list):
                has_guests = True
            if users.get('excludeUsers') and any(u[0] == 'GuestsOrExternalUsers' for u in users.get('excludeUsers', [])):
                has_guests = True
            
            if has_guests:
                applies_to_types.append('guests')
            
            if users.get('includeRoles'):
                applies_to_types.append('roles')
            if client_apps:
                # Check for regular service principals
                if client_apps.get('includeServicePrincipals'):
                    applies_to_types.append('servicePrincipals')
                # Check for agent service principals
                if client_apps.get('includeAgentIdServicePrincipals'):
                    applies_to_types.append('agents')
            
            # Determine platform types
            platform_types = []
            platforms_data = cond.get('platforms', {}) or {}
            include_platforms = platforms_data.get('includePlatforms', [])
            for platform in include_platforms:
                platform_lower = platform.lower() if isinstance(platform, str) else platform
                if platform_lower == 'android':
                    platform_types.append('android')
                elif platform_lower == 'ios':
                    platform_types.append('iOS')
                elif platform_lower == 'windows':
                    platform_types.append('windows')
                elif platform_lower == 'macos':
                    platform_types.append('macOS')
                elif platform_lower == 'linux':
                    platform_types.append('linux')
            
            # Determine risk level types
            risk_level_types = []
            if cond.get('userRiskLevels'):
                risk_level_types.append('userRisk')
            if cond.get('signInRiskLevels'):
                risk_level_types.append('signInRisk')
            if cond.get('servicePrincipalRiskLevels'):
                risk_level_types.append('servicePrincipalRisk')
            
            # Determine client app types
            client_app_types_list = cond.get('clientAppTypes', [])
            client_app_type_tags = []
            for app_type in client_app_types_list:
                if app_type == 'browser':
                    client_app_type_tags.append('browser')
                elif app_type == 'mobileAppsAndDesktopClients':
                    client_app_type_tags.append('mobileDesktop')
                elif app_type == 'exchangeActiveSync':
                    client_app_type_tags.append('exchangeActiveSync')
                elif app_type == 'other':
                    client_app_type_tags.append('otherClients')
            
            # Determine authentication flows
            auth_flow_tags = []
            auth_flows_data = cond.get('authenticationFlows', {}) or {}
            transfer_methods = auth_flows_data.get('transferMethods', '')
            if transfer_methods:
                # Handle both string and list formats
                if isinstance(transfer_methods, str):
                    methods_list = [m.strip() for m in transfer_methods.split(',')]
                else:
                    methods_list = transfer_methods if isinstance(transfer_methods, list) else []
                
                for method in methods_list:
                    # Use exact match to avoid cross-contamination
                    if method == 'deviceCodeFlow':
                        auth_flow_tags.append('deviceCodeFlow')
                    elif method == 'authenticationTransfer':
                        auth_flow_tags.append('authenticationTransfer')
            
            # Determine network types
            network_types = []
            include_locations = locations.get('includeLocations', [])
            exclude_locations = locations.get('excludeLocations', [])
            
            # Check for compliant network (special ID in include OR exclude)
            compliant_network_id = '3d46dbda-8382-466a-856d-eb00cbc6b910'
            has_compliant = any(
                loc_id == compliant_network_id 
                for loc_id, _ in (include_locations + exclude_locations)
            )
            
            # Check for trusted locations (AllTrusted or specific named locations, not All/Compliant)
            has_trusted = any(
                loc_id not in ['All', compliant_network_id] 
                for loc_id, _ in (include_locations + exclude_locations)
            )
            
            if has_compliant:
                network_types.append('compliantNetwork')
            if has_trusted:
                network_types.append('trustedLocations')
            
            # Format state display
            state_display = 'Report Only' if state == 'enabledForReportingButNotEnforced' else state.capitalize()
            
            html_parts.append(f'''
            <div class="policy-card" 
                 data-state="{state}" 
                 data-unassigned="{str(is_not_applying).lower()}"
                 data-grant-controls="{','.join(grant_control_types)}"
                 data-session-controls="{','.join(session_control_types)}"
                 data-resource-types="{','.join(resource_types)}"
                 data-applies-to="{','.join(applies_to_types)}"
                 data-network-types="{','.join(network_types)}"
                 data-platforms="{','.join(platform_types)}"
                 data-risk-levels="{','.join(risk_level_types)}"
                 data-client-app-types="{','.join(client_app_type_tags)}"
                 data-auth-flows="{','.join(auth_flow_tags)}">
                <div class="policy-card-header">
                    <div class="policy-title">{display_name}</div>
                    <div class="policy-meta">
                        <span class="policy-state-badge state-{state}">{state_display}</span>
                        {('<span class="policy-state-badge" style="background-color: #f44336; color: white; margin-left: 5px;">Not applying</span>' if is_not_applying else '')}
                        <span class="policy-id">ID: {policy_id}</span>
                    </div>
                </div>
                
                <div class="policy-card-body">
                    <table class="policy-table">
                        <tbody>
            ''')
            
            users = cond.get('users', {}) or {}
            apps = cond.get('applications', {}) or {}
            platforms = cond.get('platforms', {}) or {}
            locations = cond.get('locations', {}) or {}
            client_app_types = cond.get('clientAppTypes', []) or []
            
            # Users section
            if any([users.get('includeUsers'), users.get('excludeUsers'), 
                   users.get('includeGroups'), users.get('excludeGroups'),
                   users.get('includeRoles'), users.get('excludeRoles'),
                   users.get('includeGuestsOrExternalUsers'), users.get('excludeGuestsOrExternalUsers')]):
                html_parts.append('<tr><th>Identities</th><td>')
                
                if users.get('includeUsers'):
                    html_parts.append(f"<strong>Include Users:</strong> {self._render_with_copy_icons(users['includeUsers'])}<br/>")
                if users.get('excludeUsers'):
                    html_parts.append(f"<strong>Exclude Users:</strong> {self._render_with_copy_icons(users['excludeUsers'])}<br/>")
                if users.get('includeGroups'):
                    html_parts.append(f"<strong>Include Groups:</strong> {self._render_with_copy_icons(users['includeGroups'])}<br/>")
                if users.get('excludeGroups'):
                    html_parts.append(f"<strong>Exclude Groups:</strong> {self._render_with_copy_icons(users['excludeGroups'])}<br/>")
                if users.get('includeRoles'):
                    html_parts.append(f"<strong>Include Roles:</strong> {self._render_with_copy_icons(users['includeRoles'])}<br/>")
                if users.get('excludeRoles'):
                    html_parts.append(f"<strong>Exclude Roles:</strong> {self._render_with_copy_icons(users['excludeRoles'])}<br/>")
                
                # Guest/External users
                if users.get('includeGuestsOrExternalUsers'):
                    inc_guests = users['includeGuestsOrExternalUsers']
                    guest_types = inc_guests.get('guestOrExternalUserTypes', '').replace(',', ', ')
                    html_parts.append(f"<strong>Include Guests/External Users:</strong> {guest_types}<br/>")
                if users.get('excludeGuestsOrExternalUsers'):
                    exc_guests = users['excludeGuestsOrExternalUsers']
                    guest_types = exc_guests.get('guestOrExternalUserTypes', '').replace(',', ', ')
                    html_parts.append(f"<strong>Exclude Guests/External Users:</strong> {guest_types}<br/>")
                
                html_parts.append('</td></tr>')
            
            # Applications section
            if (apps.get('includeApplications') or apps.get('excludeApplications') or 
                apps.get('includeUserActions') or apps.get('includeAuthenticationContextClassReferences') or
                apps.get('applicationFilter')):
                html_parts.append('<tr><th>Resources</th><td>')
                
                if apps.get('includeApplications'):
                    html_parts.append(f"<strong>Include:</strong> {self._render_with_copy_icons(apps['includeApplications'])}<br/>")
                if apps.get('excludeApplications'):
                    html_parts.append(f"<strong>Exclude:</strong> {self._render_with_copy_icons(apps['excludeApplications'])}<br/>")
                if apps.get('includeUserActions'):
                    # User actions are strings, not tuples - handle specially
                    actions_display = ', '.join(apps['includeUserActions'])
                    html_parts.append(f"<strong>User Actions:</strong> {actions_display}<br/>")
                if apps.get('includeAuthenticationContextClassReferences'):
                    html_parts.append(f"<strong>Auth Context:</strong> {self._render_with_copy_icons(apps['includeAuthenticationContextClassReferences'])}<br/>")
                if apps.get('applicationFilter'):
                    app_filter = apps['applicationFilter']
                    filter_rule = app_filter.get('rule', '')
                    filter_mode = app_filter.get('mode', 'include').capitalize()
                    html_parts.append(f"<strong>App Filter ({filter_mode}):</strong> {filter_rule}<br/>")
                
                html_parts.append('</td></tr>')
            
            # Client app types
            if client_app_types:
                # Normalize client app types
                normalized_types = ['Native' if t == 'mobileAppsAndDesktopClients' else t.capitalize() 
                                  for t in client_app_types]
                html_parts.append(f'<tr><th>Client App Types</th><td>{", ".join(normalized_types)}</td></tr>')
            
            # Platforms
            if platforms.get('includePlatforms') or platforms.get('excludePlatforms'):
                html_parts.append('<tr><th>Platforms</th><td>')
                
                if platforms.get('includePlatforms'):
                    platforms_display = [p.capitalize() for p in platforms['includePlatforms']]
                    html_parts.append(f"<strong>Include:</strong> {', '.join(platforms_display)}<br/>")
                if platforms.get('excludePlatforms'):
                    platforms_display = [p.capitalize() for p in platforms['excludePlatforms']]
                    html_parts.append(f"<strong>Exclude:</strong> {', '.join(platforms_display)}")
                
                html_parts.append('</td></tr>')
            
            # Locations
            if locations.get('includeLocations') or locations.get('excludeLocations'):
                html_parts.append('<tr><th>Locations</th><td>')
                
                if locations.get('includeLocations'):
                    html_parts.append(f"<strong>Include:</strong> {self._render_with_copy_icons(locations['includeLocations'])}<br/>")
                if locations.get('excludeLocations'):
                    html_parts.append(f"<strong>Exclude:</strong> {self._render_with_copy_icons(locations['excludeLocations'])}")
                
                html_parts.append('</td></tr>')
            
            # Risk Levels
            user_risk = cond.get('userRiskLevels', [])
            signin_risk = cond.get('signInRiskLevels', [])
            sp_risk = cond.get('servicePrincipalRiskLevels', [])
            insider_risk = cond.get('insiderRiskLevels')
            
            if user_risk or signin_risk or sp_risk or insider_risk:
                html_parts.append('<tr><th>Risk Levels</th><td>')
                
                if user_risk:
                    risk_display = [r.capitalize() for r in user_risk]
                    html_parts.append(f"<strong>User Risk:</strong> {', '.join(risk_display)}<br/>")
                if signin_risk:
                    risk_display = [r.capitalize() for r in signin_risk]
                    html_parts.append(f"<strong>Sign-in Risk:</strong> {', '.join(risk_display)}<br/>")
                if sp_risk:
                    risk_display = [r.capitalize() for r in sp_risk]
                    html_parts.append(f"<strong>Service Principal Risk:</strong> {', '.join(risk_display)}<br/>")
                if insider_risk:
                    html_parts.append(f"<strong>Insider Risk:</strong> {insider_risk}")
                
                html_parts.append('</td></tr>')
            
            # Devices
            devices = cond.get('devices', {})
            if devices and devices.get('deviceFilter'):
                html_parts.append('<tr><th>Devices</th><td>')
                device_filter = devices['deviceFilter']
                filter_mode = device_filter.get('mode', 'include').capitalize()
                filter_rule = device_filter.get('rule', '')
                html_parts.append(f"<strong>Device Filter ({filter_mode}):</strong> {filter_rule}")
                html_parts.append('</td></tr>')
            
            # Authentication Flows
            auth_flows = cond.get('authenticationFlows', {})
            if auth_flows and auth_flows.get('transferMethods'):
                html_parts.append('<tr><th>Auth Flows</th><td>')
                transfer_methods_raw = auth_flows['transferMethods']
                # Handle both string and list formats from API
                if isinstance(transfer_methods_raw, str):
                    transfer_methods = transfer_methods_raw.replace(',', ', ')
                else:
                    transfer_methods = ', '.join(transfer_methods_raw)
                html_parts.append(f"<strong>Transfer Methods:</strong> {transfer_methods}")
                html_parts.append('</td></tr>')
            
            # Client Applications (Service Principals)
            client_apps = cond.get('clientApplications', {})
            if client_apps:
                if (client_apps.get('includeServicePrincipals') or 
                    client_apps.get('excludeServicePrincipals') or
                    client_apps.get('servicePrincipalFilter')):
                    html_parts.append('<tr><th>Client Apps</th><td>')
                    
                    if client_apps.get('includeServicePrincipals'):
                        html_parts.append(f"<strong>Include Service Principals:</strong> {self._render_with_copy_icons(client_apps['includeServicePrincipals'])}<br/>")
                    if client_apps.get('excludeServicePrincipals'):
                        html_parts.append(f"<strong>Exclude Service Principals:</strong> {self._render_with_copy_icons(client_apps['excludeServicePrincipals'])}<br/>")
                    if client_apps.get('servicePrincipalFilter'):
                        sp_filter = client_apps['servicePrincipalFilter']
                        filter_mode = sp_filter.get('mode', 'include').capitalize()
                        filter_rule = sp_filter.get('rule', '')
                        html_parts.append(f"<strong>Service Principal Filter ({filter_mode}):</strong> {filter_rule}")
                    
                    html_parts.append('</td></tr>')
            
            # Grant controls
            grant_controls = policy.get('grantControls', {}) or {}
            if grant_controls:
                html_parts.append('<tr><th>Grant Controls</th><td>')
                
                operator = grant_controls.get('operator', 'AND')
                built_in_controls = grant_controls.get('builtInControls', []) or []
                
                controls_list = []
                if built_in_controls:
                    # Map built-in control names to display names
                    control_map = {
                        'mfa': 'MFA',
                        'compliantDevice': 'Compliant Device',
                        'domainJoinedDevice': 'Domain Joined Device',
                        'compliantApplication': 'Compliant Application',
                        'passwordChange': 'Password Change',
                        'block': 'Block'
                    }
                    controls_display = [control_map.get(c, c.capitalize()) for c in built_in_controls]
                    
                    # Only show operator if there are 2 or more built-in controls
                    if len(built_in_controls) >= 2:
                        controls_list.append(f"{operator}: {', '.join(controls_display)}")
                    else:
                        controls_list.append(', '.join(controls_display))
                
                # Authentication Strength
                auth_strength = grant_controls.get('authenticationStrength')
                if auth_strength and isinstance(auth_strength, dict):
                    strength_name = auth_strength.get('displayName', 'Custom')
                    policy_type = auth_strength.get('policyType', '').capitalize()
                    controls_list.append(f"Auth Strength: {strength_name} ({policy_type})")
                
                # Terms of Use
                terms_of_use = grant_controls.get('termsOfUse', [])
                if terms_of_use:
                    controls_list.append(f"Terms of Use: {', '.join(terms_of_use)}")
                
                # Custom Authentication Factors
                custom_factors = grant_controls.get('customAuthenticationFactors', [])
                if custom_factors:
                    controls_list.append(f"Custom Factors: {', '.join(custom_factors)}")
                
                html_parts.append('<br/>'.join(controls_list))
                html_parts.append('</td></tr>')
            
            # Session controls
            session_controls = policy.get('sessionControls', {}) or {}
            if session_controls:
                html_parts.append('<tr><th>Session Controls</th><td>')
                
                controls_list = []
                
                # Sign-in Frequency
                if session_controls.get('signInFrequency'):
                    freq = session_controls['signInFrequency']
                    value = freq.get('value', '')
                    freq_type = freq.get('type', '')
                    auth_type = freq.get('authenticationType', '')
                    
                    # Build display string (auth_type is already cleaned up during policy processing)
                    if auth_type:
                        controls_list.append(f"Sign-in Frequency: {value} {freq_type} ({auth_type})".strip())
                    else:
                        controls_list.append(f"Sign-in Frequency: {value} {freq_type}".strip())
                
                # Persistent Browser
                if session_controls.get('persistentBrowser'):
                    persistent = session_controls['persistentBrowser']
                    if persistent and isinstance(persistent, dict):
                        mode = persistent.get('mode', '').capitalize()
                        controls_list.append(f"Persistent Browser: {mode}")
                
                # Cloud App Security
                if session_controls.get('cloudAppSecurity'):
                    cas = session_controls['cloudAppSecurity']
                    if cas and isinstance(cas, dict):
                        cas_type = cas.get('cloudAppSecurityType', '').replace('_', ' ').title()
                        controls_list.append(f"Cloud App Security: {cas_type}")
                
                # Application Enforced Restrictions
                if session_controls.get('applicationEnforcedRestrictions'):
                    app_enforced = session_controls['applicationEnforcedRestrictions']
                    if app_enforced and isinstance(app_enforced, dict):
                        is_enabled = app_enforced.get('isEnabled', False)
                        if is_enabled:
                            controls_list.append("Application Enforced Restrictions: Enabled")
                
                # Secure Sign-in Session
                if session_controls.get('secureSignInSession'):
                    secure_signin = session_controls['secureSignInSession']
                    if secure_signin and isinstance(secure_signin, dict):
                        is_enabled = secure_signin.get('isEnabled', False)
                        if is_enabled:
                            controls_list.append("Secure Sign-in Session: Enabled")
                
                # Disable Resilience Defaults
                if session_controls.get('disableResilienceDefaults'):
                    controls_list.append("Disable Resilience Defaults: True")
                
                html_parts.append('<br/>'.join(controls_list) if controls_list else 'Enabled')
                html_parts.append('</td></tr>')
            
            html_parts.append('''
                        </tbody>
                    </table>
                </div>
            </div>
            ''')
        
        html_parts.append('''
        </div>
        
        <script>
        // Copy object ID to clipboard
        function copyToClipboard(id, button) {
            event.stopPropagation(); // Prevent event bubbling
            
            // Copy to clipboard
            navigator.clipboard.writeText(id).then(() => {
                // Show feedback
                const feedback = button.querySelector('.copy-feedback');
                feedback.classList.add('show');
                
                // Hide feedback after 1.5 seconds
                setTimeout(() => {
                    feedback.classList.remove('show');
                }, 1500);
            }).catch(err => {
                console.error('Failed to copy:', err);
                alert('Failed to copy ID to clipboard');
            });
        }
        
        // Reset all filters to default values
        function resetAllFilters() {
            // Reset state filter to Enabled
            document.getElementById('policyStateFilter').value = 'enabled';
            
            // Reset all checkbox dropdowns
            const filterIds = ['grantControlFilter', 'sessionControlFilter', 'resourceTypeFilter', 
                             'appliesToFilter', 'networkFilter', 'platformFilter', 'riskLevelFilter', 'clientAppTypeFilter'];
            
            filterIds.forEach(filterId => {
                const checkboxes = document.getElementById(filterId).querySelectorAll('input[type="checkbox"]');
                checkboxes.forEach(cb => cb.checked = false);
                
                // Update label
                const labelId = filterId.replace('Filter', 'Label');
                document.getElementById(labelId).innerHTML = 'Any';
            });
            
            // Reset toggle switch
            document.getElementById('unassignedOnlyFilter').checked = false;
            
            // Reset search bar
            document.getElementById('policySearch').value = '';
            
            // Trigger filtering
            filterPolicies();
        }
        
        // Toggle dropdown visibility
        function toggleDropdown(id) {
            const dropdown = document.getElementById(id);
            const button = dropdown.previousElementSibling;
            const isOpen = dropdown.classList.contains('show');
            
            // Close all dropdowns
            document.querySelectorAll('.multi-select-options').forEach(d => {
                d.classList.remove('show');
                d.previousElementSibling.classList.remove('active');
            });
            
            // Toggle current dropdown
            if (!isOpen) {
                dropdown.classList.add('show');
                button.classList.add('active');
            }
        }
        
        // Close dropdowns when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.multi-select-dropdown')) {
                document.querySelectorAll('.multi-select-options').forEach(d => {
                    d.classList.remove('show');
                    d.previousElementSibling.classList.remove('active');
                });
            }
        });
        
        // Update filter label and trigger filtering
        function updateFilter(filterId) {
            const dropdown = document.getElementById(filterId);
            const checkboxes = dropdown.querySelectorAll('input[type="checkbox"]:checked');
            const count = checkboxes.length;
            const labelId = filterId.replace('Filter', 'Label');
            const label = document.getElementById(labelId);
            
            if (count === 0) {
                label.innerHTML = 'Any';
            } else if (count === 1) {
                label.innerHTML = checkboxes[0].nextElementSibling.textContent;
            } else {
                label.innerHTML = `${count} selected<span class="multi-select-count">${count}</span>`;
            }
            
            filterPolicies();
        }
        
        function highlightSearchTerms(searchQuery) {
            // Remove all existing highlights
            const allPolicies = document.querySelectorAll('#policyCardsContainer .policy-card');
            allPolicies.forEach(policy => {
                const highlights = policy.querySelectorAll('.search-highlight');
                highlights.forEach(highlight => {
                    const parent = highlight.parentNode;
                    parent.replaceChild(document.createTextNode(highlight.textContent), highlight);
                    parent.normalize(); // Merge adjacent text nodes
                });
            });
            
            // If no search query, we're done
            if (!searchQuery) return;
            
            // Apply new highlights to visible policies
            allPolicies.forEach(policy => {
                if (policy.style.display === 'none') return;
                
                highlightInElement(policy, searchQuery);
            });
        }
        
        function highlightInElement(element, searchQuery) {
            // Skip input elements and other non-text elements
            if (element.tagName === 'INPUT' || element.tagName === 'SCRIPT' || element.tagName === 'STYLE') {
                return;
            }
            
            // Process text nodes
            const walker = document.createTreeWalker(
                element,
                NodeFilter.SHOW_TEXT,
                null,
                false
            );
            
            const textNodes = [];
            let node;
            while (node = walker.nextNode()) {
                textNodes.push(node);
            }
            
            textNodes.forEach(textNode => {
                const text = textNode.textContent;
                const lowerText = text.toLowerCase();
                const index = lowerText.indexOf(searchQuery);
                
                if (index !== -1) {
                    // Split the text node and wrap the match
                    const before = text.substring(0, index);
                    const match = text.substring(index, index + searchQuery.length);
                    const after = text.substring(index + searchQuery.length);
                    
                    const fragment = document.createDocumentFragment();
                    if (before) fragment.appendChild(document.createTextNode(before));
                    
                    const highlight = document.createElement('span');
                    highlight.className = 'search-highlight';
                    highlight.textContent = match;
                    fragment.appendChild(highlight);
                    
                    if (after) {
                        // Recursively process the remaining text
                        const afterNode = document.createTextNode(after);
                        fragment.appendChild(afterNode);
                    }
                    
                    textNode.parentNode.replaceChild(fragment, textNode);
                }
            });
        }
        
        function filterPolicies() {
            const selectedState = document.getElementById('policyStateFilter').value;
            const searchQuery = document.getElementById('policySearch').value.toLowerCase().trim();
            
            // Get selected values from checkbox dropdowns
            const getCheckedValues = (filterId) => {
                return Array.from(document.getElementById(filterId).querySelectorAll('input[type="checkbox"]:checked'))
                    .map(cb => cb.value);
            };
            
            const selectedGrantControls = getCheckedValues('grantControlFilter');
            const selectedSessionControls = getCheckedValues('sessionControlFilter');
            const selectedResourceTypes = getCheckedValues('resourceTypeFilter');
            const selectedAppliesTo = getCheckedValues('appliesToFilter');
            const selectedNetworks = getCheckedValues('networkFilter');
            const selectedPlatforms = getCheckedValues('platformFilter');
            const selectedRiskLevels = getCheckedValues('riskLevelFilter');
            const selectedClientAppTypes = getCheckedValues('clientAppTypeFilter');
            const selectedAuthFlows = getCheckedValues('authFlowFilter');
            const unassignedOnly = document.getElementById('unassignedOnlyFilter').checked;
            const allPolicies = document.querySelectorAll('#policyCardsContainer .policy-card');
            let visibleCount = 0;
            
            allPolicies.forEach(policy => {
                const policyState = policy.getAttribute('data-state');
                const isUnassigned = policy.getAttribute('data-unassigned') === 'true';
                const grantControls = policy.getAttribute('data-grant-controls') || '';
                const sessionControls = policy.getAttribute('data-session-controls') || '';
                const resourceTypes = policy.getAttribute('data-resource-types') || '';
                const appliesTo = policy.getAttribute('data-applies-to') || '';
                const networkTypes = policy.getAttribute('data-network-types') || '';
                const platforms = policy.getAttribute('data-platforms') || '';
                const riskLevels = policy.getAttribute('data-risk-levels') || '';
                const clientAppTypes = policy.getAttribute('data-client-app-types') || '';
                const authFlowsStr = policy.getAttribute('data-auth-flows') || '';
                // Split comma-separated auth flows into array for proper matching
                const authFlows = authFlowsStr ? authFlowsStr.split(',') : [];
                
                // Check state filter
                const stateMatch = (selectedState === 'all' || policyState === selectedState);
                
                // Check grant control filter (OR logic - match any selected)
                const grantMatch = (selectedGrantControls.length === 0 || 
                    selectedGrantControls.some(control => grantControls.includes(control)));
                
                // Check session control filter (OR logic - match any selected)
                const sessionMatch = (selectedSessionControls.length === 0 || 
                    selectedSessionControls.some(control => sessionControls.includes(control)));
                
                // Check resource type filter (OR logic - match any selected)
                const resourceMatch = (selectedResourceTypes.length === 0 || 
                    selectedResourceTypes.some(type => resourceTypes.includes(type)));
                
                // Check applies to filter (OR logic - match any selected)
                const appliesToMatch = (selectedAppliesTo.length === 0 || 
                    selectedAppliesTo.some(type => appliesTo.includes(type)));
                
                // Check network filter (OR logic - match any selected)
                const networkMatch = (selectedNetworks.length === 0 || 
                    selectedNetworks.some(network => networkTypes.includes(network)));
                
                // Check platform filter (OR logic - match any selected)
                const platformMatch = (selectedPlatforms.length === 0 || 
                    selectedPlatforms.some(platform => platforms.includes(platform)));
                
                // Check risk level filter (OR logic - match any selected)
                const riskLevelMatch = (selectedRiskLevels.length === 0 || 
                    selectedRiskLevels.some(risk => riskLevels.includes(risk)));
                
                // Check client app type filter (OR logic - match any selected)
                const clientAppTypeMatch = (selectedClientAppTypes.length === 0 || 
                    selectedClientAppTypes.some(type => clientAppTypes.includes(type)));
                
                // Check authentication flow filter (OR logic - match any selected)
                // authFlows is an array, selectedAuthFlows is an array - check if any selected flow is in the policy's flows
                const authFlowMatch = (selectedAuthFlows.length === 0 || 
                    selectedAuthFlows.some(flow => authFlows.includes(flow)));
                
                // Check unassigned filter
                const unassignedMatch = !unassignedOnly || isUnassigned;
                
                // Check search filter
                const searchMatch = !searchQuery || policy.textContent.toLowerCase().includes(searchQuery);
                
                // Show policy only if ALL filters match (AND logic between categories, OR within categories)
                if (stateMatch && grantMatch && sessionMatch && resourceMatch && 
                    appliesToMatch && networkMatch && platformMatch && riskLevelMatch && 
                    clientAppTypeMatch && authFlowMatch && unassignedMatch && searchMatch) {
                    policy.style.display = 'block';
                    visibleCount++;
                } else {
                    policy.style.display = 'none';
                }
            });
            
            // Apply highlighting to visible policies
            highlightSearchTerms(searchQuery);
            
            document.getElementById('policyBrowserCount').textContent = 
                `Showing ${visibleCount} of ${allPolicies.length} policies`;
        }
        
        // Initialize count on load
        if (document.getElementById('policyStateFilter')) {
            filterPolicies();
        }
        </script>
        ''')
        
        return ''.join(html_parts)
    
    def _save_cache_updates(self, id_cache: Dict[str, str], app_cache: Dict[str, str], 
                           progress_callback = None):
        """Save updated caches back to disk to persist cache misses.
        
        This merges new entries from id_cache and app_cache back into their
        respective cache files, ensuring cache misses are persisted.
        
        Parameters:
            id_cache (Dict[str, str]): Updated ID-to-name cache
            app_cache (Dict[str, str]): Updated appId-to-name cache
            progress_callback (callable, optional): Callback function for progress updates
        """
        if progress_callback:
            progress_callback(92, "Saving cache updates...")
        
        try:
            # Update individual cache files with new entries
            cache_files_to_update = [
                (Path('cache') / 'policies' / 'users.json', '#microsoft.graph.user'),
                (Path('cache') / 'policies' / 'groups.json', '#microsoft.graph.group'),
                (Path('cache') / 'policies' / 'roles.json', '#microsoft.graph.directoryRole'),
                (Path('cache') / 'policies' / 'service-principals.json', '#microsoft.graph.servicePrincipal'),
                (Path('cache') / 'policies' / 'auth-contexts.json', None),  
            ]
            
            # For each cache file, add new entries from id_cache
            for cache_file, odata_type in cache_files_to_update:
                if not cache_file.exists():
                    continue
                    
                try:
                    with open(cache_file, 'r') as f:
                        objects = json.load(f)
                    
                    # Build set of existing IDs
                    existing_ids = {obj.get('id') for obj in objects if obj.get('id')}
                    
                    # Add new entries from id_cache that aren't already in the file
                    added_count = 0
                    for obj_id, display_name in id_cache.items():
                        if obj_id not in existing_ids and obj_id != display_name:
                            # Create minimal object with id and displayName
                            new_obj = {'id': obj_id, 'displayName': display_name}
                            if odata_type:
                                new_obj['@odata.type'] = odata_type
                            objects.append(new_obj)
                            added_count += 1
                    
                    # Save back if we added anything
                    if added_count > 0:
                        with open(cache_file, 'w') as f:
                            json.dump(objects, f, indent=2)
                        print(f"  → Added {added_count} new entries to {cache_file.name}")
                        
                except Exception as e:
                    print(f"Warning: Could not update {cache_file.name}: {e}")
            
            # Update applications cache with new entries from app_cache
            applications_file = Path('cache') / 'policies' / 'applications.json'
            if applications_file.exists():
                try:
                    with open(applications_file, 'r') as f:
                        apps = json.load(f)
                    
                    # Build set of existing appIds
                    existing_app_ids = {app.get('appId') for app in apps if app.get('appId')}
                    
                    # Add new entries from app_cache
                    added_count = 0
                    for app_id, display_name in app_cache.items():
                        if app_id not in existing_app_ids and app_id != display_name:
                            apps.append({'appId': app_id, 'displayName': display_name})
                            added_count += 1
                    
                    # Save back if we added anything
                    if added_count > 0:
                        with open(applications_file, 'w') as f:
                            json.dump(apps, f, indent=2)
                        print(f"  → Added {added_count} new entries to {applications_file.name}")
                        
                except Exception as e:
                    print(f"Warning: Could not update {applications_file.name}: {e}")
                    
        except Exception as e:
            print(f"Warning: Could not save cache updates: {e}")
    
    def _resolve_list(self, items, id_cache, loc_lookup):
        """Resolve a list of IDs to display names using cached data.
        
        Parameters:
            items (list): List of IDs or ID-containing objects
            id_cache (dict): Cache of previously resolved IDs from object_map.json
            loc_lookup (dict): Mapping of location IDs to display names
        
        Returns:
            list: List of tuples (id, display_name) for tooltip support
        """
        if not items:
            return []
        
        resolved = []
        for item in items:
            if isinstance(item, dict) and 'id' in item:
                obj_id = item['id']
            elif isinstance(item, str):
                obj_id = item
            else:
                # For non-ID items, use the value for both ID and display
                resolved.append((str(item), str(item)))
                continue
            
            # Special handling for well-known CA values and location IDs
            # Check case-insensitively for special CA values (All, None, AllTrusted, etc.)
            if obj_id in SPECIAL_CA_VALUES or (isinstance(obj_id, str) and obj_id.capitalize() in SPECIAL_CA_VALUES):
                # Return the properly cased version if available
                display_name = obj_id.capitalize() if obj_id.capitalize() in SPECIAL_CA_VALUES else obj_id
            elif obj_id == '3d46dbda-8382-466a-856d-eb00cbc6b910':
                display_name = 'All Compliant Network locations'
            elif obj_id == 'AllTrusted' or obj_id == 'allTrusted':
                display_name = 'All trusted networks and locations'
            else:
                # Look up in cache (falls back to original ID if not found)
                display_name = id_cache.get(obj_id, obj_id)
            resolved.append((obj_id, display_name))
        
        return resolved
    
    def _render_with_copy_icons(self, items):
        """Render a list of (id, name) tuples as HTML with click-to-copy icons.
        
        Parameters:
            items (list): List of tuples (id, display_name)
        
        Returns:
            str: Comma-separated HTML with copy buttons for IDs
        """
        if not items:
            return ""
        
        html_parts = []
        for obj_id, display_name in items:
            # Special handling for well-known constants (no copy button needed)
            if obj_id in SPECIAL_CA_VALUES:
                html_parts.append(display_name)
            else:
                # Add copy button that appears on hover
                html_parts.append(f'''<span class="id-container">{display_name}<button class="copy-id-btn" onclick="copyToClipboard('{obj_id}', this)" title="Copy ID: {obj_id}"><svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg><span class="copy-feedback">Copied!</span></button></span>''')
        
        return ', '.join(html_parts)

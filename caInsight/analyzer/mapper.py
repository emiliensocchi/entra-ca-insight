"""
User and group mapping for policy evaluation
"""

# Standard library imports
import json
import shutil
from pathlib import Path
from typing import List, Dict, Set

# Local imports
from ..graph.api_client import GraphAPIClient


class UserMapper:
    """Maps users, groups, and roles for policy evaluation"""
    
    @staticmethod
    def _cache_has_valid_content(cache_file: Path) -> bool:
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

    def __init__(self, api_client: GraphAPIClient):
        """Initialize the user mapper.
        
        Sets up cache directory and file paths for storing object mappings,
        application mappings, and group membership links related to policies.
        
        Parameters:
            api_client (GraphAPIClient): Graph API client for resolving directory objects
        """
        self.api_client = api_client
        self.cache_dir = Path("cache/policies")
        self.cache_dir.mkdir(exist_ok=True)
        # Assignments
        self.users_file = self.cache_dir / "users.json"
        self.groups_file = self.cache_dir / "groups.json"
        self.roles_file = self.cache_dir / "roles.json"
        self.agent_identities_file = self.cache_dir / "agent-identities.json"
        self.service_principals_file = self.cache_dir / "service-principals.json"
        # Target resources
        self.applications_file = self.cache_dir / "applications.json"
        self.agent_resources_file = self.cache_dir / "agent-resources.json"
        # Extras for Policy Browser
        self.auth_contexts_file = self.cache_dir / "auth-contexts.json"
    
    def populate_users_cache(self, policies: List[Dict], skip_object_ids: Set[str] = None, progress_callback = None) -> List[Dict]:
        """Populate users cache from policies.
        
        Parameters:
            policies: List of CA policies
            skip_object_ids: Set of object IDs to skip
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of user objects
        """
        skip_ids = skip_object_ids or set()
        
        if self._cache_has_valid_content(self.users_file):
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect user IDs from policies
        user_ids = set()
        for policy in policies:
            users = policy.get('conditions', {}).get('users', {})
            for field in ['includeUsers', 'excludeUsers']:
                values = users.get(field, [])
                for value in values:
                    if value and value not in ['None', 'GuestsOrExternalUsers', 'All'] and value not in skip_ids:
                        user_ids.add(value)
        
        objects, deleted_ids = self.api_client.resolve_objects(list(user_ids))
        users = [obj for obj in objects if obj.get('@odata.type') == '#microsoft.graph.user']
        
        # Clean up policies - remove deleted user references
        if deleted_ids:
            for policy in policies:
                users_cond = policy.get('conditions', {}).get('users', {})
                for field in ['includeUsers', 'excludeUsers']:
                    if field in users_cond and users_cond[field]:
                        users_cond[field] = [uid for uid in users_cond[field] if uid not in deleted_ids]
        
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
        
        return users
    
    def populate_groups_cache(self, policies: List[Dict], skip_object_ids: Set[str] = None, progress_callback = None) -> List[Dict]:
        """Populate groups cache from policies.
        
        Parameters:
            policies: List of CA policies
            skip_object_ids: Set of object IDs to skip
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of group objects
        """
        skip_ids = skip_object_ids or set()
        
        if self._cache_has_valid_content(self.groups_file):
            with open(self.groups_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect group IDs from policies
        group_ids = set()
        for policy in policies:
            users = policy.get('conditions', {}).get('users', {})
            for field in ['includeGroups', 'excludeGroups']:
                values = users.get(field, [])
                for value in values:
                    if value and value not in ['None', 'GuestsOrExternalUsers', 'All'] and value not in skip_ids:
                        group_ids.add(value)
        
        objects, deleted_ids = self.api_client.resolve_objects(list(group_ids))
        groups = [obj for obj in objects if obj.get('@odata.type') == '#microsoft.graph.group']
        
        # Clean up policies - remove deleted group references
        if deleted_ids:
            if progress_callback:
                progress_callback(25, f"Removing {len(deleted_ids)} deleted group references from policies")
            for policy in policies:
                users_cond = policy.get('conditions', {}).get('users', {})
                for field in ['includeGroups', 'excludeGroups']:
                    if field in users_cond and users_cond[field]:
                        users_cond[field] = [gid for gid in users_cond[field] if gid not in deleted_ids]
        
        self.groups_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.groups_file, 'w', encoding='utf-8') as f:
            json.dump(groups, f, indent=2)
        
        return groups
    
    def populate_roles_cache(self, policies: List[Dict], skip_object_ids: Set[str] = None, progress_callback = None) -> List[Dict]:
        """Populate roles cache from policies.
        
        Parameters:
            policies: List of CA policies
            skip_object_ids: Set of object IDs to skip
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of role objects
        """
        skip_ids = skip_object_ids or set()
        
        if self._cache_has_valid_content(self.roles_file):
            with open(self.roles_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect role IDs from policies
        role_ids = set()
        for policy in policies:
            users = policy.get('conditions', {}).get('users', {})
            for field in ['includeRoles', 'excludeRoles']:
                values = users.get(field, [])
                for value in values:
                    if value and value not in ['None', 'GuestsOrExternalUsers', 'All'] and value not in skip_ids:
                        role_ids.add(value)
        
        objects, deleted_ids = self.api_client.resolve_objects(list(role_ids))
        roles = [obj for obj in objects if obj.get('@odata.type') == '#microsoft.graph.directoryRole' or 
                 obj.get('@odata.type') == '#microsoft.graph.directoryRoleTemplate']
        
        # Clean up policies - remove deleted role references
        if deleted_ids:
            for policy in policies:
                users_cond = policy.get('conditions', {}).get('users', {})
                for field in ['includeRoles', 'excludeRoles']:
                    if field in users_cond and users_cond[field]:
                        users_cond[field] = [rid for rid in users_cond[field] if rid not in deleted_ids]
        
        self.roles_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.roles_file, 'w', encoding='utf-8') as f:
            json.dump(roles, f, indent=2)
        
        return roles

    def populate_agent_identities_cache(self, policies: List[Dict], progress_callback = None) -> List[Dict]:
        """Populate agent identities cache from policies.
        
        Parameters:
            policies: List of CA policies
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of agent identity service principal objects
        """
        if self._cache_has_valid_content(self.agent_identities_file):
            with open(self.agent_identities_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect agent identity service principal IDs from policies
        sp_ids = set()
        for policy in policies:
            client_apps = policy.get('conditions', {}).get('clientApplications') or {}
            for field in ['includeAgentIdServicePrincipals', 'excludeAgentIdServicePrincipals']:
                values = client_apps.get(field, [])
                for value in values:
                    if value and value not in ['All']:
                        sp_ids.add(value)
        
        service_principals = self.api_client.resolve_service_principals_by_ids(list(sp_ids))
        
        # Determine which service principal IDs failed to resolve
        resolved_sp_ids = {sp.get('id') for sp in service_principals if sp.get('id')}
        failed_sp_ids = sp_ids - resolved_sp_ids
        
        # Clean up policies - remove failed service principal references
        if failed_sp_ids:
            for policy in policies:
                client_apps = policy.get('conditions', {}).get('clientApplications') or {}
                for field in ['includeServicePrincipals', 'excludeServicePrincipals']:
                    if field in client_apps and client_apps[field]:
                        client_apps[field] = [spid for spid in client_apps[field] if spid not in failed_sp_ids]
        
        self.agent_identities_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.agent_identities_file, 'w', encoding='utf-8') as f:
            json.dump(service_principals, f, indent=2)
        
        return service_principals

    def populate_service_principals_cache(self, policies: List[Dict], progress_callback = None) -> List[Dict]:
        """Populate service principals cache from policies.
        
        Parameters:
            policies: List of CA policies
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of service principal objects
        """
        if self._cache_has_valid_content(self.service_principals_file):
            with open(self.service_principals_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect service principal IDs from policies
        sp_ids = set()
        for policy in policies:
            client_apps = policy.get('conditions', {}).get('clientApplications') or {}
            for field in ['includeServicePrincipals', 'excludeServicePrincipals']:
                values = client_apps.get(field, [])
                for value in values:
                    if value and value not in ['All']:
                        sp_ids.add(value)
        
        service_principals = self.api_client.resolve_service_principals_by_ids(list(sp_ids))
        
        # Determine which service principal IDs failed to resolve
        resolved_sp_ids = {sp.get('id') for sp in service_principals if sp.get('id')}
        failed_sp_ids = sp_ids - resolved_sp_ids
        
        # Clean up policies - remove failed service principal references
        if failed_sp_ids:
            for policy in policies:
                client_apps = policy.get('conditions', {}).get('clientApplications') or {}
                for field in ['includeServicePrincipals', 'excludeServicePrincipals']:
                    if field in client_apps and client_apps[field]:
                        client_apps[field] = [spid for spid in client_apps[field] if spid not in failed_sp_ids]
        
        self.service_principals_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.service_principals_file, 'w', encoding='utf-8') as f:
            json.dump(service_principals, f, indent=2)
        
        return service_principals
    
    def populate_applications_cache(self, policies: List[Dict], progress_callback = None) -> List[Dict]:
        """Populate applications cache from policies.
        
        Parameters:
            policies: List of CA policies
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of application (service principal) objects
        """
        if self._cache_has_valid_content(self.applications_file):
            with open(self.applications_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect application IDs from policies
        app_ids = set()
        for policy in policies:
            apps = policy.get('conditions', {}).get('applications', {})
            for field in ['includeApplications', 'excludeApplications']:
                values = apps.get(field, [])
                for value in values:
                    if value and value not in ['All', 'AllAgentIdResources']:
                        app_ids.add(value)
        
        apps = []
        failed_app_ids = set()
        for app_id in app_ids:
            app = self.api_client.resolve_service_principal(app_id)
            if app:
                apps.append(app)
            else:
                failed_app_ids.add(app_id)
        
        # Clean up policies - remove failed application references
        if failed_app_ids:
            for policy in policies:
                apps_condition = policy.get('conditions', {}).get('applications', {})
                for field in ['includeApplications', 'excludeApplications']:
                    if field in apps_condition and apps_condition[field]:
                        apps_condition[field] = [aid for aid in apps_condition[field] if aid not in failed_app_ids]
        
        self.applications_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.applications_file, 'w', encoding='utf-8') as f:
            json.dump(apps, f, indent=2)
        
        return apps

    def populate_agent_resources_cache(self, policies: List[Dict], progress_callback = None) -> List[Dict]:
        """Populate agent resources cache from policies.

        Parameters:
            policies: List of CA policies
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of agent resource service principal objects
        """
        if self._cache_has_valid_content(self.agent_resources_file):
            with open(self.agent_resources_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect agent resource IDs from policies
        resource_ids = set()
        for policy in policies:
            apps = policy.get('conditions', {}).get('applications', {})
            for field in ['includeApplications', 'excludeApplications']:
                values = apps.get(field, [])
                for value in values:
                    if value and value not in ['All', 'AllAgentIdResources']:
                        resource_ids.add(value)
        
        agent_resources = self.api_client.resolve_agent_resources_by_ids(list(resource_ids))
        
        # Determine which IDs failed to resolve
        resolved_ids = {sp.get('id') for sp in agent_resources if sp.get('id')}
        failed_ids = resource_ids - resolved_ids
        
        # Clean up policies - remove failed agent resource references
        if failed_ids:
            for policy in policies:
                apps_condition = policy.get('conditions', {}).get('applications', {})
                for field in ['includeApplications', 'excludeApplications']:
                    if field in apps_condition and apps_condition[field]:
                        apps_condition[field] = [aid for aid in apps_condition[field] if aid not in failed_ids]
        
        self.agent_resources_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.agent_resources_file, 'w', encoding='utf-8') as f:
            json.dump(agent_resources, f, indent=2)
        
        return agent_resources

    def populate_auth_contexts_cache(self, policies: List[Dict], progress_callback = None) -> List[Dict]:
        """Populate authentication contexts cache from policies.
        
        Parameters:
            policies: List of CA policies
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List of authentication context objects
        """
        if self._cache_has_valid_content(self.auth_contexts_file):
            with open(self.auth_contexts_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Collect auth context IDs from policies
        auth_context_ids = set()
        for policy in policies:
            apps = policy.get('conditions', {}).get('applications', {})
            auth_contexts = apps.get('includeAuthenticationContextClassReferences', [])
            for ctx_id in auth_contexts:
                if ctx_id:
                    auth_context_ids.add(ctx_id)
        
        # Fetch all authentication contexts
        auth_contexts = self.api_client.get_authentication_contexts(use_cache=True)
        
        # Determine which auth context IDs don't exist
        valid_auth_context_ids = {ctx.get('id') for ctx in auth_contexts if ctx.get('id')}
        invalid_auth_context_ids = auth_context_ids - valid_auth_context_ids
        
        # Clean up policies - remove invalid auth context references
        if invalid_auth_context_ids:
            for policy in policies:
                apps_condition = policy.get('conditions', {}).get('applications', {})
                if 'includeAuthenticationContextClassReferences' in apps_condition and apps_condition['includeAuthenticationContextClassReferences']:
                    apps_condition['includeAuthenticationContextClassReferences'] = [
                        ctx_id for ctx_id in apps_condition['includeAuthenticationContextClassReferences'] 
                        if ctx_id not in invalid_auth_context_ids
                    ]
        
        self.auth_contexts_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.auth_contexts_file, 'w', encoding='utf-8') as f:
            json.dump(auth_contexts, f, indent=2)
        
        return auth_contexts
        
    def load_users(self) -> List[Dict]:
        """Load the users mapping from cache.
        
        Returns:
            List[Dict]: List of user objects, or empty list if cache doesn't exist
        """
        if self.users_file.exists():
            with open(self.users_file, 'r') as f:
                return json.load(f)
        return []
        
    def load_groups(self) -> List[Dict]:
        """Load the groups mapping from cache.
        
        Returns:
            List[Dict]: List of group objects, or empty list if cache doesn't exist
        """
        if self.groups_file.exists():
            with open(self.groups_file, 'r') as f:
                return json.load(f)
        return []
        
    def load_roles(self) -> List[Dict]:
        """Load the roles mapping from cache.
        
        Returns:
            List[Dict]: List of role objects, or empty list if cache doesn't exist
        """
        if self.roles_file.exists():
            with open(self.roles_file, 'r') as f:
                return json.load(f)
        return []
        
    def load_applications(self) -> List[Dict]:
        """Load the applications mapping from cache.
        
        Returns:
            List[Dict]: List of application/service principal objects, or empty list if cache doesn't exist
        """
        if self.applications_file.exists():
            with open(self.applications_file, 'r') as f:
                return json.load(f)
        return []
    
    def load_service_principals(self) -> List[Dict]:
        """Load the service principals mapping from cache.
        
        Returns:
            List[Dict]: List of service principal objects, or empty list if cache doesn't exist
        """
        if self.service_principals_file.exists():
            with open(self.service_principals_file, 'r') as f:
                return json.load(f)
        return []
    
    def load_auth_contexts(self) -> List[Dict]:
        """Load the authentication contexts mapping from cache.
        
        Returns:
            List[Dict]: List of authentication context class references, or empty list if cache doesn't exist
        """
        if self.auth_contexts_file.exists():
            with open(self.auth_contexts_file, 'r') as f:
                return json.load(f)
        return []
        
    def clear_mapping_cache(self, mode: str = 'all'):
        """Clear mapping caches based on specified mode.
        
        Parameters:
            mode (str): Cache clearing mode - 'all', 'policies', or 'tenant'
                       - 'all': Clear all caches (entire cache directory)
                       - 'policies': Clear only policy-specific caches (cache/policies/ subdirectory)
                       - 'tenant': Clear only tenant-wide caches (cache/tenant/ subdirectory)
        """
        if not self.cache_dir.exists():
            return
            
        if mode == 'all':
            # Clear everything in cache directory
            for item in self.cache_dir.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
        elif mode == 'policies':
            # Clear only cache/policies/ subdirectory
            policies_dir = self.cache_dir / 'policies'
            if policies_dir.exists():
                shutil.rmtree(policies_dir)
                policies_dir.mkdir(parents=True, exist_ok=True)
        elif mode == 'tenant':
            # Clear only cache/tenant/ subdirectory
            tenant_dir = self.cache_dir / 'tenant'
            if tenant_dir.exists():
                shutil.rmtree(tenant_dir)
                tenant_dir.mkdir(parents=True, exist_ok=True)

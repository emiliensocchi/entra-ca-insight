"""
Identity filter configuration management for CA Insight.

Handles loading, validating, and applying identity filters from JSON files.
"""

# Standard library imports
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class FilterConfig:
    """Manages identity filter configuration for inclusions and exclusions."""
    
    # Regex pattern to detect GUIDs (8-4-4-4-12 format)
    GUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    
    def __init__(self, filter_data: Dict = None, graph_client=None):
        """Initialize filter configuration.
        
        Args:
            filter_data: Dictionary with 'include' and 'exclude' keys, each containing
                        either a list of IDs (legacy) or dict with users/groups/roles (new)
            graph_client: Optional GraphAPIClient (not used in __init__, kept for compatibility)
        """
        # Initialize type-specific sets
        self.include_users: Set[str] = set()
        self.include_groups: Set[str] = set()
        self.include_roles: Set[str] = set()
        self.exclude_users: Set[str] = set()
        self.exclude_groups: Set[str] = set()
        self.exclude_roles: Set[str] = set()
        
        # Initialize flattened ID sets for filtering
        self.include_ids: Set[str] = set()
        self.exclude_ids: Set[str] = set()
        
        if filter_data:
            self._load_filter_data(filter_data)
    
    def _load_filter_data(self, data: Dict):
        """Load and parse filter data in both legacy and new formats.
        
        Args:
            data: Dictionary with 'include' and 'exclude' keys
        """
        # Process include filters
        include_data = data.get('include', [])
        if isinstance(include_data, dict):
            # New structured format
            self.include_users = set(include_data.get('users', []))
            self.include_groups = set(include_data.get('groups', []))
            self.include_roles = set(include_data.get('roles', []))
            # Add user GUIDs directly to include_ids
            for user_id in self.include_users:
                if self._is_guid(user_id):
                    self.include_ids.add(user_id)
        elif isinstance(include_data, list):
            # Legacy flat format - treat all as users
            self.include_users = set(include_data)
            # Add GUIDs to include_ids
            for user_id in self.include_users:
                if self._is_guid(user_id):
                    self.include_ids.add(user_id)
        
        # Process exclude filters
        exclude_data = data.get('exclude', [])
        if isinstance(exclude_data, dict):
            # New structured format
            self.exclude_users = set(exclude_data.get('users', []))
            self.exclude_groups = set(exclude_data.get('groups', []))
            self.exclude_roles = set(exclude_data.get('roles', []))
            # Add user GUIDs directly to exclude_ids
            for user_id in self.exclude_users:
                if self._is_guid(user_id):
                    self.exclude_ids.add(user_id)
        elif isinstance(exclude_data, list):
            # Legacy flat format - treat all as users
            self.exclude_users = set(exclude_data)
            # Add GUIDs to exclude_ids
            for user_id in self.exclude_users:
                if self._is_guid(user_id):
                    self.exclude_ids.add(user_id)
    
    def _is_guid(self, value: str) -> bool:
        """Check if a string is a valid GUID.
        
        Args:
            value: String to check
        
        Returns:
            True if value matches GUID pattern (8-4-4-4-12)
        """
        return bool(self.GUID_PATTERN.match(value))
    
    @classmethod
    def from_file(cls, file_path: str, graph_client=None) -> 'FilterConfig':
        """Load filter configuration from JSON file.
        
        Args:
            file_path: Path to JSON filter file
            graph_client: Optional GraphAPIClient for resolving groups/roles
            
        Returns:
            FilterConfig instance
            
        Raises:
            FileNotFoundError: If filter file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
            ValueError: If file format is invalid
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Filter file not found: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate structure
        if not isinstance(data, dict):
            raise ValueError("Filter file must contain a JSON object")
        
        # Validate include field
        if 'include' in data:
            if isinstance(data['include'], dict):
                # New format: validate sub-fields
                for field in ['users', 'groups', 'roles']:
                    if field in data['include'] and not isinstance(data['include'][field], list):
                        raise ValueError(f"'include.{field}' must be a list of object IDs")
            elif not isinstance(data['include'], list):
                raise ValueError("'include' must be a list or dict with users/groups/roles")
        
        # Validate exclude field
        if 'exclude' in data:
            if isinstance(data['exclude'], dict):
                # New format: validate sub-fields
                for field in ['users', 'groups', 'roles']:
                    if field in data['exclude'] and not isinstance(data['exclude'][field], list):
                        raise ValueError(f"'exclude.{field}' must be a list of object IDs")
            elif not isinstance(data['exclude'], list):
                raise ValueError("'exclude' must be a list or dict with users/groups/roles")
        
        return cls(data, graph_client)
    
    @classmethod
    def from_legacy_params(cls, include_ids: str = None, exclude_ids: str = None) -> 'FilterConfig':
        """Create filter config from legacy comma-separated ID parameters.
        
        Args:
            include_ids: Comma-separated list of IDs to include
            exclude_ids: Comma-separated list of IDs to exclude
            
        Returns:
            FilterConfig instance
        """
        data = {}
        
        if include_ids:
            data['include'] = [id.strip() for id in include_ids.split(',') if id.strip()]
        
        if exclude_ids:
            data['exclude'] = [id.strip() for id in exclude_ids.split(',') if id.strip()]
        
        return cls(data)
    
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate filter configuration for conflicts.
        
        Returns:
            Tuple of (is_valid, list_of_conflicting_ids)
        """
        conflicts = self.include_ids & self.exclude_ids
        return (len(conflicts) == 0, sorted(conflicts))
    
    def has_filters(self) -> bool:
        """Check if any filters are configured.
        
        Returns:
            True if include or exclude filters are present
        """
        return len(self.include_ids) > 0 or len(self.exclude_ids) > 0
    
    def has_include_filter(self) -> bool:
        """Check if include filter is configured."""
        return len(self.include_ids) > 0
    
    def has_exclude_filter(self) -> bool:
        """Check if exclude filter is configured."""
        return len(self.exclude_ids) > 0
    
    def get_include_ids(self) -> List[str]:
        """Get list of IDs to include."""
        return sorted(self.include_ids)
    
    def get_exclude_ids(self) -> List[str]:
        """Get list of IDs to exclude."""
        return sorted(self.exclude_ids)
    
    def resolve_names_to_ids(self, graph_client):
        """Resolve display names to object IDs.
        
        Args:
            graph_client: GraphAPIClient instance for lookups
        """
        self.graph_client = graph_client
        
        # Resolve include user display names (UPN or displayName)
        for value in list(self.include_users):
            if not self._is_guid(value):
                try:
                    # Try to find user by UPN or display name
                    user_id = self._resolve_user_name(graph_client, value)
                    if user_id:
                        self.include_ids.add(user_id)
                        print(f"✓ Resolved include user '{value}' to {user_id}")
                    else:
                        print(f"[WARN] Could not resolve include user name: {value}")
                except Exception as e:
                    print(f"[WARN] Failed to resolve include user '{value}': {e}")
        
        # Resolve exclude user display names
        for value in list(self.exclude_users):
            if not self._is_guid(value):
                try:
                    user_id = self._resolve_user_name(graph_client, value)
                    if user_id:
                        self.exclude_ids.add(user_id)
                        print(f"✓ Resolved exclude user '{value}' to {user_id}")
                    else:
                        print(f"[WARN] Could not resolve exclude user name: {value}")
                except Exception as e:
                    print(f"[WARN] Failed to resolve exclude user '{value}': {e}")
        
        # Resolve include group IDs/names
        for value in self.include_groups:
            try:
                if not self._is_guid(value):
                    # It's a display name, resolve it
                    group_id = self._resolve_group_name(graph_client, value)
                    if not group_id:
                        print(f"[WARN] Could not resolve include group name: {value}")
                        continue
                else:
                    group_id = value
                
                # Get members
                members = graph_client.get_group_members(group_id)
                user_ids = {m['id'] for m in members if m.get('id')}
                self.include_ids.update(user_ids)
                print(f"✓ Resolved include group '{value}' to {len(user_ids)} user(s)")
            except Exception as e:
                print(f"[WARN] Failed to resolve include group '{value}': {e}")
        
        # Resolve include role IDs/names
        for value in self.include_roles:
            try:
                if not self._is_guid(value):
                    # It's a display name, resolve it
                    role_id = self._resolve_role_name(graph_client, value)
                    if not role_id:
                        print(f"[WARN] Could not resolve include role name: {value}")
                        continue
                else:
                    role_id = value
                
                # Get members
                members = graph_client.get_directory_role_members(role_id)
                user_ids = {m['id'] for m in members if m.get('id')}
                self.include_ids.update(user_ids)
                print(f"✓ Resolved include role '{value}' to {len(user_ids)} user(s)")
            except Exception as e:
                print(f"[WARN] Failed to resolve include role '{value}': {e}")
        
        # Resolve exclude groups
        for value in self.exclude_groups:
            try:
                if not self._is_guid(value):
                    group_id = self._resolve_group_name(graph_client, value)
                    if not group_id:
                        print(f"[WARN] Could not resolve exclude group name: {value}")
                        continue
                else:
                    group_id = value
                
                members = graph_client.get_group_members(group_id)
                user_ids = {m['id'] for m in members if m.get('id')}
                self.exclude_ids.update(user_ids)
                print(f"✓ Resolved exclude group '{value}' to {len(user_ids)} user(s)")
            except Exception as e:
                print(f"[WARN] Failed to resolve exclude group '{value}': {e}")
        
        # Resolve exclude roles
        for value in self.exclude_roles:
            try:
                if not self._is_guid(value):
                    role_id = self._resolve_role_name(graph_client, value)
                    if not role_id:
                        print(f"[WARN] Could not resolve exclude role name: {value}")
                        continue
                else:
                    role_id = value
                
                members = graph_client.get_directory_role_members(role_id)
                user_ids = {m['id'] for m in members if m.get('id')}
                self.exclude_ids.update(user_ids)
                print(f"✓ Resolved exclude role '{value}' to {len(user_ids)} user(s)")
            except Exception as e:
                print(f"[WARN] Failed to resolve exclude role '{value}': {e}")
    
    def _resolve_user_name(self, graph_client, name: str) -> Optional[str]:
        """Resolve user display name or UPN to object ID."""
        # Try as UPN first (most common)
        users = graph_client.get_users_by_filter(f"userPrincipalName eq '{name}'")
        if users:
            return users[0].get('id')
        
        # Try as displayName
        users = graph_client.get_users_by_filter(f"displayName eq '{name}'")
        if users:
            return users[0].get('id')
        
        return None
    
    def _resolve_group_name(self, graph_client, name: str) -> Optional[str]:
        """Resolve group display name to object ID."""
        groups = graph_client.get_groups_by_filter(f"displayName eq '{name}'")
        if groups:
            return groups[0].get('id')
        return None
    
    def _resolve_role_name(self, graph_client, name: str) -> Optional[str]:
        """Resolve role display name to object ID."""
        roles = graph_client.get_directory_roles_by_filter(f"displayName eq '{name}'")
        if roles:
            return roles[0].get('id')
        return None
    
    # Keep old method name for backward compatibility
    def resolve_groups_and_roles(self, graph_client):
        """Resolve groups, roles, and display names to IDs. Wrapper for resolve_names_to_ids."""
        self.resolve_names_to_ids(graph_client)
    
    def to_dict(self, use_new_format: bool = True) -> Dict:
        """Export configuration as dictionary.
        
        Args:
            use_new_format: If True, export with separate arrays for users/groups/roles.
                          If False, export legacy flat format.
        
        Returns:
            Dictionary with 'include' and 'exclude' keys
        """
        if use_new_format:
            return {
                'include': {
                    'users': sorted(self.include_users),
                    'groups': sorted(self.include_groups),
                    'roles': sorted(self.include_roles)
                },
                'exclude': {
                    'users': sorted(self.exclude_users),
                    'groups': sorted(self.exclude_groups),
                    'roles': sorted(self.exclude_roles)
                }
            }
        else:
            # Legacy format
            return {
                'include': self.get_include_ids(),
                'exclude': self.get_exclude_ids()
            }
    
    def save(self, file_path: str):
        """Save filter configuration to JSON file.
        
        Args:
            file_path: Path where to save the filter file
        """
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    def __repr__(self) -> str:
        """String representation of filter config."""
        return f"FilterConfig(include={len(self.include_ids)}, exclude={len(self.exclude_ids)})"

"""
Policy flattening module - resolves groups and roles to their members with PIM support.

This module flattens conditional access policies by resolving all group and role assignments
to their direct member identities. This enables gap analysis by ensuring
all policies explicitly reference the individual identities they affect.
"""

import copy
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

from ..graph.api_client import GraphAPIClient


class PolicyFlattener:
    """Flattens conditional access policies by resolving groups and roles to members"""
    
    def __init__(self, api_client: GraphAPIClient, cache_dir: Path = None):
        """Initialize the policy flattener.
        
        Parameters:
            api_client (GraphAPIClient): Graph API client for fetching data
            cache_dir (Path): Directory for caching flattened policies (default: 'cache')
        """
        self.api_client = api_client
        self.cache_dir = cache_dir or Path("cache")
        self.cache_dir.mkdir(exist_ok=True)
    
    def flatten_policies_for_users(self, policies: List[Dict], target_resources: str, progress_callback = None) -> List[Dict]:
        """Flatten policies by resolving groups and roles to user members.
        
        For users-groups-roles workflows:
        - Resolves all groups to their user members (recursive, includes nested groups)
        - Resolves all roles to their user members (includes PIM eligible assignments)
        - Stores flattened policies in cache/policies/flat-policies-users.json
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects
            target_resources (str): Target resource type for the analysis ('cloud-apps', 'user-actions', 'agent-resources')
            progress_callback: Optional callback for progress reporting
        
        Returns:
            List[Dict]: Flattened policies with groups/roles resolved to user IDs
        """
        cache_file = self.cache_dir / "policies" / f"flat-policies-users-{target_resources}.json"
        
        # Check if cache exists and load from it
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                flattened_policies = json.load(f)
            return flattened_policies
                
        # Build resolution maps (optimized to minimize API calls)
        msg = "Building group membership map (with PIM eligibility)..."
        print(msg)
        if progress_callback:
            progress_callback(27, msg)
        group_to_users = self._build_group_to_users_map(progress_callback=progress_callback)
        
        msg = "Building role membership map (with PIM eligibility)..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        role_to_users = self._build_role_to_users_map(progress_callback=progress_callback)
        
        # Flatten each policy
        flattened_policies = []
        
        for policy in policies:
            flattened = self._flatten_policy_for_users(policy, group_to_users, role_to_users)
            flattened_policies.append(flattened)
        
        # Cache flattened policies
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(flattened_policies, f, indent=2)
        
        msg = f"✓ Flattened {len(flattened_policies)} policies cached to cache"
        print(msg)
        if progress_callback:
            progress_callback(30, msg)
        
        return flattened_policies
    
    def flatten_policies_for_guests(self, policies: List[Dict], target_resources: str, progress_callback = None) -> Tuple[List[Dict], Dict[str, bool]]:
        """Flatten policies by resolving special guest/external user values to actual user IDs.
        
        For guests workflows:
        - Resolves special values like 'GuestsOrExternalUsers', 'internalGuest', 'b2bCollaborationGuest', etc.
        - Each special value is replaced with the corresponding user IDs
        - Non-resolvable values (b2bDirectConnectUser, otherExternalUser, serviceProvider) are tracked separately
        - Stores flattened policies in cache/policies/flat-policies-guests.json
        
        Special guest types and their resolution:
        - internalGuest → Local guest users (userType=Guest, homed in tenant)
        - b2bCollaborationGuest → B2B collaboration guest users (userType=Guest, from external tenant)
        - b2bCollaborationMember → B2B collaboration member users (userType=Member, from external tenant)
        - b2bDirectConnectUser → Cannot be resolved (shared channels users, no directory object)
        - otherExternalUser → Cannot be resolved (catch-all for other external users)
        - serviceProvider → Cannot be resolved (GDAP/CSP partner admins)
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects
            target_resources (str): Target resource type for the analysis ('cloud-apps', 'user-actions', 'agent-resources')
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Tuple[List[Dict], Dict[str, bool]]: 
                - Flattened policies with guest values resolved to user IDs
                - Dict of non-resolvable guest types and whether they have universal coverage
        """
        cache_file = self.cache_dir / "policies" / f"flat-policies-guests-{target_resources}.json"
        metadata_file = self.cache_dir / "policies" / f"flat-policies-guests-metadata-{target_resources}.json"
        
        # Check if cache exists and load from it
        if cache_file.exists() and metadata_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                flattened_policies = json.load(f)
            with open(metadata_file, 'r', encoding='utf-8') as f:
                non_resolvable_coverage = json.load(f)
            return flattened_policies, non_resolvable_coverage
        
        # Build resolution maps for resolvable guest types
        msg = "Building guest type resolution maps..."
        print(msg)
        if progress_callback:
            progress_callback(27, msg)
        
        guest_type_maps = self._build_guest_type_maps(progress_callback=progress_callback)
        
        # Track non-resolvable guest types and their coverage
        non_resolvable_types = ['b2bDirectConnectUser', 'otherExternalUser', 'serviceProvider']
        non_resolvable_coverage = {gt: False for gt in non_resolvable_types}
        
        # Flatten each policy
        msg = "Flattening policies for guest types..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        
        flattened_policies = []
        
        for policy in policies:
            flattened, covered_non_resolvable = self._flatten_policy_for_guests(policy, guest_type_maps)
            flattened_policies.append(flattened)
            
            # Track coverage for non-resolvable types
            for gt in covered_non_resolvable:
                if gt in non_resolvable_coverage:
                    non_resolvable_coverage[gt] = True
        
        # Cache flattened policies and metadata
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(flattened_policies, f, indent=2)
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(non_resolvable_coverage, f, indent=2)
        
        msg = f"✓ Flattened {len(flattened_policies)} policies for guests cached to cache"
        print(msg)
        if progress_callback:
            progress_callback(30, msg)
        
        return flattened_policies, non_resolvable_coverage
    
    def flatten_policies_for_agents(self, policies: List[Dict], target_resources: str, progress_callback = None) -> List[Dict]:
        """Flatten policies by resolving roles to agent identity members.
        
        For agent-identities workflows:
        - Resolves all roles to their agent identity members (includes PIM eligible assignments)
        - Stores flattened policies in cache/flat_policies_agent_identities.json
        
        Note: Agent identities can have role assignments but NOT group memberships.
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects
            target_resources (str): Target resource type for the analysis ('cloud-apps', 'agent-resources')
            progress_callback: Optional callback for progress reporting
        
        Returns:
            List[Dict]: Flattened policies with roles resolved to agent identity IDs
        """
        cache_file = self.cache_dir / "policies" / f"flat_policies_agent_identities-{target_resources}.json"
 
        # Check if cache exists and load from it
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                flattened_policies = json.load(f)
            return flattened_policies

        # Build role resolution map for agent identities
        msg = "Building role membership map for agent identities (with PIM eligibility)..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        role_to_agents = self._build_role_to_agents_map(progress_callback=progress_callback)
        
        # Flatten each policy
        flattened_policies = []
        
        for policy in policies:
            flattened = self._flatten_policy_for_agents(policy, role_to_agents)
            flattened_policies.append(flattened)
        
        # Cache flattened policies
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(flattened_policies, f, indent=2)
        
        msg = f"✓ Flattened {len(flattened_policies)} policies cached to cache"
        print(msg)
        if progress_callback:
            progress_callback(30, msg)
        
        return flattened_policies
    
    def flatten_policies_for_workloads(self, policies: List[Dict], target_resources: str, progress_callback = None) -> List[Dict]:
        """Flatten policies by resolving roles to workload identity members.
        
        For workload-identities workflows:
        - Resolves all roles to their workload identity members (NO PIM support for workloads)
        - Stores flattened policies in cache/flat_policies_workload_identities.json
        
        Note: Workload identities can have role assignments but NOT group memberships or PIM.
        
        Parameters:
            policies (List[Dict]): List of conditional access policy objects
            target_resources (str): Target resource type for the analysis ('cloud-apps', 'agent-resources')
            progress_callback: Optional callback for progress reporting
        
        Returns:
            List[Dict]: Flattened policies with roles resolved to workload identity IDs
        """
        cache_file = self.cache_dir / "policies" / f"flat_policies_workload_identities-{target_resources}.json"
        
        # Check if cache exists and load from it
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                flattened_policies = json.load(f)
            return flattened_policies
        
        # Build role resolution map for workload identities (no PIM)
        msg = "Building role membership map for workload identities..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        role_to_workloads = self._build_role_to_workloads_map(progress_callback=progress_callback)
        
        # Flatten each policy
        flattened_policies = []
        
        for policy in policies:
            flattened = self._flatten_policy_for_workloads(policy, role_to_workloads)
            flattened_policies.append(flattened)
        
        # Cache flattened policies
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(flattened_policies, f, indent=2)
        
        msg = f"✓ Flattened {len(flattened_policies)} policies cached to cache"
        print(msg)
        if progress_callback:
            progress_callback(30, msg)
        
        return flattened_policies
    
    def _build_group_to_users_map(self, progress_callback = None) -> Dict[str, Set[str]]:
        """Build a map of group ID -> set of user IDs (includes PIM eligible members).
        
        Parameters:
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Dict[str, Set[str]]: Map of group_id -> set of user_ids
        """
        group_map = defaultdict(set)
        
        # Get all groups from cache
        groups_cache = self.cache_dir / "policies" / "groups.json"

        if not groups_cache.exists():
            msg = "  Warning: groups.json cache not found, returning empty map"
            print(msg)
            if progress_callback:
                progress_callback(27, msg)
            return dict(group_map)
        
        with open(groups_cache, 'r', encoding='utf-8') as f:
            groups = json.load(f)
        
        # Resolve each group to its members (recursive for nested groups)
        for i, group in enumerate(groups):
            if i > 0 and i % 50 == 0:
                msg = f"  Resolved {i}/{len(groups)} groups..."
                print(msg)
                if progress_callback:
                    progress_callback(27, msg)
            
            group_id = group.get('id')
            if not group_id:
                continue
            
            # Get all user members (recursive)
            user_members = self._get_all_user_members_recursive(group_id, set())
            group_map[group_id] = user_members
        
        # Add PIM eligible group members
        msg = "  Adding PIM eligible group members..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        pim_group_members = self._get_pim_eligible_group_members()
        for group_id, eligible_users in pim_group_members.items():
            group_map[group_id].update(eligible_users)
        
        msg = f"  ✓ Resolved {len(group_map)} groups to user members"
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        return dict(group_map)
    
    def _build_role_to_users_map(self, progress_callback = None) -> Dict[str, Set[str]]:
        """Build a map of role ID -> set of user IDs (includes PIM eligible assignments).
        
        Parameters:
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Dict[str, Set[str]]: Map of role_id -> set of user_ids
        """
        role_map = defaultdict(set)
        
        # Get all roles from cache
        roles_cache = self.cache_dir / "policies" / "roles.json"
        if not roles_cache.exists():
            msg = "  Warning: roles.json cache not found, returning empty map"
            print(msg)
            if progress_callback:
                progress_callback(28, msg)
            return dict(role_map)
        
        with open(roles_cache, 'r', encoding='utf-8') as f:
            roles = json.load(f)
        
        # Resolve each role to its members
        for i, role in enumerate(roles):
            if i > 0 and i % 20 == 0:
                msg = f"  Resolved {i}/{len(roles)} roles..."
                print(msg)
                if progress_callback:
                    progress_callback(28, msg)
            
            role_id = role.get('roleTemplateId') or role.get('id')
            if not role_id:
                continue
            
            # Get active role members
            members = self.api_client.get_role_members(role_id)
            for member in members:
                # Only include users (type check)
                if member.get('@odata.type') == '#microsoft.graph.user':
                    role_map[role_id].add(member.get('id'))
        
        # Add PIM eligible role members
        msg = "  Adding PIM eligible role members..."
        print(msg)
        if progress_callback:
            progress_callback(29, msg)
        pim_role_members = self._get_pim_eligible_role_members()
        for role_id, eligible_users in pim_role_members.items():
            role_map[role_id].update(eligible_users)
        
        msg = f"  ✓ Resolved {len(role_map)} roles to user members"
        print(msg)
        if progress_callback:
            progress_callback(29, msg)
        return dict(role_map)
    
    def _build_guest_type_maps(self, progress_callback = None) -> Dict[str, Set[str]]:
        """Build maps of guest type -> set of user IDs for resolvable guest types.
        
        Resolvable guest types:
        - internalGuest → Local guest users (userType=Guest, homed in tenant)
        - b2bCollaborationGuest → B2B collaboration guest users
        - b2bCollaborationMember → B2B collaboration member users
        
        Non-resolvable guest types (not included):
        - b2bDirectConnectUser → Users in shared channels, no directory object
        - otherExternalUser → Catch-all for other external users
        - serviceProvider → GDAP/CSP partner admins
        
        Parameters:
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Dict[str, Set[str]]: Map of guest_type -> set of user_ids
        """
        guest_type_maps = {}
        
        # internalGuest: Local guest users
        msg = "  Fetching internal guest users..."
        print(msg)
        if progress_callback:
            progress_callback(27, msg)
        internal_guests = self.api_client.get_internal_guests(use_cache=True)
        guest_type_maps['internalGuest'] = {g.get('id') for g in internal_guests if g.get('id')}
        
        # b2bCollaborationGuest: B2B collaboration guest users
        msg = "  Fetching B2B collaboration guest users..."
        print(msg)
        if progress_callback:
            progress_callback(27, msg)
        b2b_guests = self.api_client.get_b2b_collaboration_guests(use_cache=True)
        guest_type_maps['b2bCollaborationGuest'] = {g.get('id') for g in b2b_guests if g.get('id')}
        
        # b2bCollaborationMember: B2B collaboration member users
        msg = "  Fetching B2B collaboration member users..."
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        b2b_members = self.api_client.get_b2b_collaboration_members(use_cache=True)
        guest_type_maps['b2bCollaborationMember'] = {g.get('id') for g in b2b_members if g.get('id')}
        
        # Also build a combined set for "GuestsOrExternalUsers" legacy keyword
        # This includes all resolvable guest types
        all_resolvable_guests = set()
        all_resolvable_guests.update(guest_type_maps['internalGuest'])
        all_resolvable_guests.update(guest_type_maps['b2bCollaborationGuest'])
        all_resolvable_guests.update(guest_type_maps['b2bCollaborationMember'])
        guest_type_maps['GuestsOrExternalUsers'] = all_resolvable_guests
        
        # Also fetch all guest users for the 'All' case
        all_guests = self.api_client.get_all_active_guests(use_cache=True)
        guest_type_maps['AllGuests'] = {g.get('id') for g in all_guests if g.get('id')}
        
        msg = f"  ✓ Built guest type maps: {len(guest_type_maps['internalGuest'])} internal, {len(guest_type_maps['b2bCollaborationGuest'])} B2B guests, {len(guest_type_maps['b2bCollaborationMember'])} B2B members"
        print(msg)
        if progress_callback:
            progress_callback(28, msg)
        
        return guest_type_maps
    
    def _build_role_to_agents_map(self, progress_callback = None) -> Dict[str, Set[str]]:
        """Build a map of role ID -> set of agent identity IDs (includes PIM eligible).
        
        Parameters:
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Dict[str, Set[str]]: Map of role_id -> set of agent_ids
        """
        role_map = defaultdict(set)
        
        # Get all roles from cache
        roles_cache = self.cache_dir / "policies" / "roles.json"
        if not roles_cache.exists():
            msg = "  Warning: roles.json cache not found, returning empty map"
            print(msg)
            if progress_callback:
                progress_callback(28, msg)
            return dict(role_map)
        
        with open(roles_cache, 'r', encoding='utf-8') as f:
            roles = json.load(f)
        
        # Get all agent identities
        agent_identities = self._get_all_agent_identities()
        agent_ids = {agent.get('id') for agent in agent_identities if agent.get('id')}
        
        # Resolve each role to its members (filter to agent identities only)
        for i, role in enumerate(roles):
            if i > 0 and i % 20 == 0:
                msg = f"  Resolved {i}/{len(roles)} roles..."
                print(msg)
                if progress_callback:
                    progress_callback(28, msg)
            
            role_id = role.get('roleTemplateId') or role.get('id')
            if not role_id:
                continue
            
            # Get active role members
            members = self.api_client.get_role_members(role_id)
            for member in members:
                member_id = member.get('id')
                # Only include agent identities
                if member_id and member_id in agent_ids:
                    role_map[role_id].add(member_id)
        
        # Add PIM eligible role members (agent identities)
        msg = "  Adding PIM eligible role members for agent identities..."
        print(msg)
        if progress_callback:
            progress_callback(29, msg)
        pim_role_members = self._get_pim_eligible_role_members()
        for role_id, eligible_principals in pim_role_members.items():
            # Filter to only agent identities
            eligible_agents = eligible_principals & agent_ids
            role_map[role_id].update(eligible_agents)
        
        msg = f"  ✓ Resolved {len(role_map)} roles to agent identity members"
        print(msg)
        if progress_callback:
            progress_callback(29, msg)
        return dict(role_map)
    
    def _build_role_to_workloads_map(self, progress_callback = None) -> Dict[str, Set[str]]:
        """Build a map of role ID -> set of workload identity IDs (NO PIM support).
        
        Parameters:
            progress_callback: Optional callback for progress reporting
        
        Returns:
            Dict[str, Set[str]]: Map of role_id -> set of workload_ids
        """
        role_map = defaultdict(set)
        
        # Get all roles from cache
        roles_cache = self.cache_dir / "policies" / "roles.json"
        if not roles_cache.exists():
            msg = "  Warning: roles.json cache not found, returning empty map"
            print(msg)
            if progress_callback:
                progress_callback(28, msg)
            return dict(role_map)
        
        with open(roles_cache, 'r', encoding='utf-8') as f:
            roles = json.load(f)
        
        # Get all workload identities (service principals)
        workload_identities = self._get_all_workload_identities()
        workload_ids = {sp.get('id') for sp in workload_identities if sp.get('id')}
        
        # Resolve each role to its members (filter to workload identities only)
        for i, role in enumerate(roles):
            if i > 0 and i % 20 == 0:
                msg = f"  Resolved {i}/{len(roles)} roles..."
                print(msg)
                if progress_callback:
                    progress_callback(28, msg)
            
            role_id = role.get('roleTemplateId') or role.get('id')
            if not role_id:
                continue
            
            # Get active role members
            members = self.api_client.get_role_members(role_id)
            for member in members:
                member_id = member.get('id')
                # Only include workload identities (service principals)
                if member_id and member_id in workload_ids:
                    role_map[role_id].add(member_id)
        
        # Note: Workload identities do NOT support PIM
        
        msg = f"  ✓ Resolved {len(role_map)} roles to workload identity members"
        print(msg)
        if progress_callback:
            progress_callback(29, msg)
        return dict(role_map)
    
    def _get_all_user_members_recursive(self, group_id: str, visited: Set[str]) -> Set[str]:
        """Get all user members of a group recursively (handles nested groups).
        
        Parameters:
            group_id (str): The group ID to resolve
            visited (Set[str]): Set of already visited group IDs (prevents infinite loops)
        
        Returns:
            Set[str]: Set of user IDs that are members of this group
        """
        if group_id in visited:
            return set()  # Prevent infinite recursion
        
        visited.add(group_id)
        user_ids = set()
        
        # Get direct members
        members = self.api_client.get_group_members(group_id)
        
        for member in members:
            member_type = member.get('@odata.type', '')
            member_id = member.get('id')
            
            if not member_id:
                continue
            
            if member_type == '#microsoft.graph.user':
                # Direct user member
                user_ids.add(member_id)
            elif member_type == '#microsoft.graph.group':
                # Nested group - recurse
                nested_users = self._get_all_user_members_recursive(member_id, visited)
                user_ids.update(nested_users)
        
        return user_ids
    
    def _get_pim_eligible_group_members(self) -> Dict[str, Set[str]]:
        """Get PIM eligible group members (users eligible for group membership).
        
        Returns:
            Dict[str, Set[str]]: Map of group_id -> set of eligible user_ids
        """
        # Query: /identityGovernance/privilegedAccess/group/eligibilityScheduleInstances
        # This returns all active PIM eligibility assignments for groups
        
        url = f"https://{self.api_client.msgraph_domain}/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances"
        url += "?$expand=principal,group&$top=999"
        
        headers = {
            "Authorization": f"Bearer {self.api_client.token}",
            "Content-Type": "application/json"
        }
        
        eligible_map = defaultdict(set)
        
        try:
            while url:
                response = self.api_client.session.get(url, headers=headers, timeout=30)
                
                if response.status_code == 404:
                    # PIM not available or no permissions
                    print("    PIM group eligibility data not available (404)")
                    break
                elif response.status_code == 403:
                    print("    Insufficient permissions to read PIM group eligibility")
                    break
                elif response.status_code != 200:
                    print(f"    Failed to fetch PIM group eligibility: {response.status_code}")
                    break
                
                data = response.json()
                instances = data.get('value', [])
                
                for instance in instances:
                    # Get group ID
                    group_data = instance.get('group', {})
                    group_id = group_data.get('id')
                    
                    # Get principal (user) ID
                    principal_data = instance.get('principal', {})
                    principal_id = principal_data.get('id')
                    principal_type = principal_data.get('@odata.type', '')
                    
                    # Only include users (not other principal types)
                    if group_id and principal_id and principal_type == '#microsoft.graph.user':
                        eligible_map[group_id].add(principal_id)
                
                url = data.get('@odata.nextLink')
            
            print(f"    ✓ Found {sum(len(v) for v in eligible_map.values())} PIM eligible group memberships")
            
        except Exception as e:
            print(f"    Warning: Failed to fetch PIM group eligibility: {e}")
        
        return dict(eligible_map)
    
    def _get_pim_eligible_role_members(self) -> Dict[str, Set[str]]:
        """Get PIM eligible role members (principals eligible for role assignment).
        
        Returns:
            Dict[str, Set[str]]: Map of role_id -> set of eligible principal_ids
        """
        # Query: /roleManagement/directory/roleEligibilityScheduleInstances
        # This returns all active PIM eligibility assignments for directory roles
        
        url = f"https://{self.api_client.msgraph_domain}/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
        url += "?$expand=principal,roleDefinition&$top=999"
        
        headers = {
            "Authorization": f"Bearer {self.api_client.token}",
            "Content-Type": "application/json"
        }
        
        eligible_map = defaultdict(set)
        
        try:
            while url:
                response = self.api_client.session.get(url, headers=headers, timeout=30)
                
                if response.status_code == 404:
                    # PIM not available or no permissions
                    print("    PIM role eligibility data not available (404)")
                    break
                elif response.status_code == 403:
                    print("    Insufficient permissions to read PIM role eligibility")
                    break
                elif response.status_code != 200:
                    print(f"    Failed to fetch PIM role eligibility: {response.status_code}")
                    break
                
                data = response.json()
                instances = data.get('value', [])
                
                for instance in instances:
                    # Get role definition ID
                    role_data = instance.get('roleDefinition', {})
                    role_id = role_data.get('id')  # This is the roleTemplateId
                    
                    # Get principal ID (can be user, agent, or service principal)
                    principal_data = instance.get('principal', {})
                    principal_id = principal_data.get('id')
                    
                    if role_id and principal_id:
                        eligible_map[role_id].add(principal_id)
                
                url = data.get('@odata.nextLink')
            
            print(f"    ✓ Found {sum(len(v) for v in eligible_map.values())} PIM eligible role assignments")
            
        except Exception as e:
            print(f"    Warning: Failed to fetch PIM role eligibility: {e}")
        
        return dict(eligible_map)
    
    def _get_all_agent_identities(self) -> List[Dict]:
        """Get all agent identities in the tenant.
        
        Returns:
            List[Dict]: List of agent identity objects
        """
        # Agent identities are service principals with a specific tag
        # For now, use cached service principals if available
        
        sp_cache = self.cache_dir / "policies" / "service-principals.json"
        if sp_cache.exists():
            with open(sp_cache, 'r', encoding='utf-8') as f:
                all_sps = json.load(f)
            
            # Filter to agent identities (those with agentId tag)
            # This is a placeholder - adjust based on actual agent ID detection logic
            agent_ids = [sp for sp in all_sps if sp.get('tags') and 'AgentId' in sp.get('tags', [])]
            return agent_ids
        
        # If not cached, return empty list
        return []
    
    def _get_all_workload_identities(self) -> List[Dict]:
        """Get all workload identities (service principals) in the tenant.
        
        Returns:
            List[Dict]: List of service principal objects
        """
        sp_cache = self.cache_dir / "policies" / "service-principals.json"
        if sp_cache.exists():
            with open(sp_cache, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # If not cached, return empty list
        return []
    
    def _flatten_policy_for_users(self, policy: Dict, group_map: Dict[str, Set[str]], 
                                   role_map: Dict[str, Set[str]]) -> Dict:
        """Flatten a single policy by resolving groups and roles to user IDs.
        
        Parameters:
            policy (Dict): Original policy object
            group_map (Dict[str, Set[str]]): Map of group_id -> user_ids
            role_map (Dict[str, Set[str]]): Map of role_id -> user_ids
        
        Returns:
            Dict: Flattened policy with groups/roles resolved
        """
        flattened = policy.copy()
        conditions = flattened.get('conditions', {})
        users_section = conditions.get('users', {})
        
        # Resolve includeGroups -> includeUsers
        include_groups = users_section.get('includeGroups', [])
        if include_groups:
            resolved_users = set(users_section.get('includeUsers', []))
            for group_id in include_groups:
                if group_id in group_map:
                    resolved_users.update(group_map[group_id])
            
            # Update policy
            users_section['includeUsers'] = list(resolved_users)
            users_section['includeGroups'] = []  # Clear groups
        
        # Resolve excludeGroups -> excludeUsers
        exclude_groups = users_section.get('excludeGroups', [])
        if exclude_groups:
            resolved_users = set(users_section.get('excludeUsers', []))
            for group_id in exclude_groups:
                if group_id in group_map:
                    resolved_users.update(group_map[group_id])
            
            # Update policy
            users_section['excludeUsers'] = list(resolved_users)
            users_section['excludeGroups'] = []  # Clear groups
        
        # Resolve includeRoles -> includeUsers
        include_roles = users_section.get('includeRoles', [])
        if include_roles:
            resolved_users = set(users_section.get('includeUsers', []))
            for role_id in include_roles:
                if role_id in role_map:
                    resolved_users.update(role_map[role_id])
            
            # Update policy
            users_section['includeUsers'] = list(resolved_users)
            users_section['includeRoles'] = []  # Clear roles
        
        # Resolve excludeRoles -> excludeUsers
        exclude_roles = users_section.get('excludeRoles', [])
        if exclude_roles:
            resolved_users = set(users_section.get('excludeUsers', []))
            for role_id in exclude_roles:
                if role_id in role_map:
                    resolved_users.update(role_map[role_id])
            
            # Update policy
            users_section['excludeUsers'] = list(resolved_users)
            users_section['excludeRoles'] = []  # Clear roles
        
        return flattened
    
    def _flatten_policy_for_guests(self, policy: Dict, guest_type_maps: Dict[str, Set[str]]) -> Tuple[Dict, List[str]]:
        """Flatten a single policy by resolving guest/external user types to user IDs.
        
        Handles both modern and legacy guest targeting:
        - Modern: users.includeGuestsOrExternalUsers.guestOrExternalUserTypes
        - Modern: users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes
        - Legacy: 'GuestsOrExternalUsers' keyword in users.includeUsers/excludeUsers
        
        Parameters:
            policy (Dict): Original policy object
            guest_type_maps (Dict[str, Set[str]]): Map of guest_type -> user_ids
        
        Returns:
            Tuple[Dict, List[str]]: 
                - Flattened policy with guest types resolved to user IDs
                - List of non-resolvable guest types that are covered by this policy (for gap reporting)
                  NOTE: Only returns non-resolvable types if the policy has strong controls (block/mfa/auth strength)
        """
        flattened = copy.deepcopy(policy)
        conditions = flattened.get('conditions', {})
        users_section = conditions.get('users', {})
        
        covered_non_resolvable = []
        non_resolvable_types = {'b2bDirectConnectUser', 'otherExternalUser', 'serviceProvider'}
        
        # Check if policy has strong controls (block/mfa/auth strength)
        # Only policies with strong controls count as "coverage" for non-resolvable guest types
        grant_controls = policy.get('grantControls') or {}
        built_in_controls = grant_controls.get('builtInControls') or []
        auth_strength = grant_controls.get('authenticationStrength')
        has_strong_controls = any(c in ['block', 'mfa'] for c in built_in_controls) or auth_strength
        
        # === Handle includeGuestsOrExternalUsers (modern) ===
        include_guests_or_external = users_section.get('includeGuestsOrExternalUsers')
        if include_guests_or_external:
            guest_types_str = include_guests_or_external.get('guestOrExternalUserTypes', '')
            guest_types = [gt.strip() for gt in guest_types_str.split(',') if gt.strip()]
            
            # Resolve to user IDs and track non-resolvable types
            resolved_users = set(users_section.get('includeUsers', []))
            for gt in guest_types:
                if gt in non_resolvable_types:
                    # Only track coverage if policy has strong controls
                    if has_strong_controls:
                        covered_non_resolvable.append(gt)
                elif gt in guest_type_maps:
                    resolved_users.update(guest_type_maps[gt])
            
            # Update policy
            users_section['includeUsers'] = list(resolved_users)
            users_section['includeGuestsOrExternalUsers'] = None  # Clear the original
        
        # === Handle excludeGuestsOrExternalUsers (modern) ===
        exclude_guests_or_external = users_section.get('excludeGuestsOrExternalUsers')
        if exclude_guests_or_external:
            guest_types_str = exclude_guests_or_external.get('guestOrExternalUserTypes', '')
            guest_types = [gt.strip() for gt in guest_types_str.split(',') if gt.strip()]
            
            # Resolve to user IDs
            resolved_users = set(users_section.get('excludeUsers', []))
            for gt in guest_types:
                if gt in guest_type_maps and gt not in non_resolvable_types:
                    resolved_users.update(guest_type_maps[gt])
            
            # Update policy
            users_section['excludeUsers'] = list(resolved_users)
            users_section['excludeGuestsOrExternalUsers'] = None  # Clear the original
        
        # === Handle legacy 'GuestsOrExternalUsers' keyword in includeUsers ===
        include_users = users_section.get('includeUsers', [])
        if 'GuestsOrExternalUsers' in include_users:
            # Remove the keyword and add all resolvable guests
            resolved_users = set(u for u in include_users if u != 'GuestsOrExternalUsers')
            resolved_users.update(guest_type_maps.get('GuestsOrExternalUsers', set()))
            users_section['includeUsers'] = list(resolved_users)
            
            # Legacy keyword covers all guest types including non-resolvable
            # Only count as coverage if policy has strong controls
            if has_strong_controls:
                for gt in non_resolvable_types:
                    if gt not in covered_non_resolvable:
                        covered_non_resolvable.append(gt)
        
        # === Handle legacy 'GuestsOrExternalUsers' keyword in excludeUsers ===
        exclude_users = users_section.get('excludeUsers', [])
        if 'GuestsOrExternalUsers' in exclude_users:
            # Remove the keyword and add all resolvable guests
            resolved_users = set(u for u in exclude_users if u != 'GuestsOrExternalUsers')
            resolved_users.update(guest_type_maps.get('GuestsOrExternalUsers', set()))
            users_section['excludeUsers'] = list(resolved_users)
        
        return flattened, covered_non_resolvable
    
    def _flatten_policy_for_agents(self, policy: Dict, role_map: Dict[str, Set[str]]) -> Dict:
        """Flatten a single policy by resolving roles to agent identity IDs.
        
        Parameters:
            policy (Dict): Original policy object
            role_map (Dict[str, Set[str]]): Map of role_id -> agent_ids
        
        Returns:
            Dict: Flattened policy with roles resolved to agent IDs
        """
        flattened = policy.copy()
        conditions = flattened.get('conditions', {})
        
        # Agent identities are in clientApplications section
        client_apps = conditions.get('clientApplications', {})
        users_section = conditions.get('users', {})  # Roles might be in users section
        
        # Resolve roles from users section -> clientApplications.includeAgentIdServicePrincipals
        include_roles = users_section.get('includeRoles', [])
        if include_roles:
            resolved_agents = set(client_apps.get('includeAgentIdServicePrincipals', []))
            for role_id in include_roles:
                if role_id in role_map:
                    resolved_agents.update(role_map[role_id])
            
            # Update policy
            client_apps['includeAgentIdServicePrincipals'] = list(resolved_agents)
            users_section['includeRoles'] = []  # Clear roles
        
        # Resolve roles from users section -> clientApplications.excludeAgentIdServicePrincipals
        exclude_roles = users_section.get('excludeRoles', [])
        if exclude_roles:
            resolved_agents = set(client_apps.get('excludeAgentIdServicePrincipals', []))
            for role_id in exclude_roles:
                if role_id in role_map:
                    resolved_agents.update(role_map[role_id])
            
            # Update policy
            client_apps['excludeAgentIdServicePrincipals'] = list(resolved_agents)
            users_section['excludeRoles'] = []  # Clear roles
        
        return flattened
    
    def _flatten_policy_for_workloads(self, policy: Dict, role_map: Dict[str, Set[str]]) -> Dict:
        """Flatten a single policy by resolving roles to workload identity IDs.
        
        Parameters:
            policy (Dict): Original policy object
            role_map (Dict[str, Set[str]]): Map of role_id -> workload_ids
        
        Returns:
            Dict: Flattened policy with roles resolved to workload IDs
        """
        flattened = policy.copy()
        conditions = flattened.get('conditions', {})
        
        # Workload identities are in clientApplications section
        client_apps = conditions.get('clientApplications', {})
        users_section = conditions.get('users', {})  # Roles might be in users section
        
        # Resolve roles from users section -> clientApplications.includeServicePrincipals
        include_roles = users_section.get('includeRoles', [])
        if include_roles:
            resolved_workloads = set(client_apps.get('includeServicePrincipals', []))
            for role_id in include_roles:
                if role_id in role_map:
                    resolved_workloads.update(role_map[role_id])
            
            # Update policy
            client_apps['includeServicePrincipals'] = list(resolved_workloads)
            users_section['includeRoles'] = []  # Clear roles
        
        # Resolve roles from users section -> clientApplications.excludeServicePrincipals
        exclude_roles = users_section.get('excludeRoles', [])
        if exclude_roles:
            resolved_workloads = set(client_apps.get('excludeServicePrincipals', []))
            for role_id in exclude_roles:
                if role_id in role_map:
                    resolved_workloads.update(role_map[role_id])
            
            # Update policy
            client_apps['excludeServicePrincipals'] = list(resolved_workloads)
            users_section['excludeRoles'] = []  # Clear roles
        
        return flattened

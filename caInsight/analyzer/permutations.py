"""
Per-identity permutation generation for conditional access policy analysis.

This module generates permutations on a per-identity basis, where each identity
gets their own set of permutations based on the analysis workflow type.
"""

import json
from itertools import product
from pathlib import Path
from typing import List, Dict, Set


class PermutationGenerator:
    """Generates per-identity permutations for gap analysis"""

    @staticmethod
    def _load_resource_ids_from_cache(cache_path: Path, id_field: str = 'id') -> List[str]:
        """Load resource IDs from a tenant cache file.

        Parameters:
            cache_path: Path to the JSON cache file
            id_field: Field name to extract as the resource ID (default: 'id')

        Returns:
            List of non-empty ID strings; empty list if the cache is missing or unreadable
        """
        if not cache_path.exists():
            return []
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return [obj[id_field] for obj in data if isinstance(obj, dict) and obj.get(id_field)]
        except (json.JSONDecodeError, IOError):
            return []
    
    def generate_permutations_for_users(
        self,
        user_ids: List[str],
        target_resource: str,
        named_locations: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Generate permutations for users-groups-roles workflow.
        
        For each user, generates permutations following the pattern:
        clientAppType * authFlow * location * (application OR userAction)
        
        Parameters:
            user_ids (List[str]): List of user IDs to generate permutations for
            target_resource (str): Target resource type ('cloud-apps', 'user-actions', 'agent-resources')
            named_locations (List[Dict]): List of named location objects
        
        Returns:
            Dict[str, List[Dict]]: Map of user_id -> list of permutation dicts
        """
        # Build dimension value sets
        # Authentication flows: static set
        auth_flows = ['none', 'deviceCodeFlow', 'authenticationTransfer']
        
        # Client application types: static set
        client_app_types = ['all', 'browser', 'mobileAppsAndDesktopClients', 
                           'exchangeActiveSync', 'other']
        
        # Locations: 'All', 'AllTrusted', plus all named locations
        locations = ['All', 'AllTrusted']
        for loc in named_locations:
            locations.append(loc.get('id'))
        
        # Removed for now, as it is an easily-bypassable condition
        #platforms = ['all', 'android', 'iOS', 'windows', 'macOS', 'linux', 'unknown']

        # Resource dimension resolved on-demand based on target
        if target_resource == 'user-actions':
            resources = ['registerSecurityInformation', 'registerOrJoinDevices']
            resource_key = 'userAction'
        elif target_resource == 'agent-resources':
            agent_resource_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'agent-resources.json'
            )
            resources = ['AllAgentIdResources'] + agent_resource_ids
            resource_key = 'application'
        else:  # cloud-apps
            cloud_app_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'applications.json'
            )
            resources = ['All'] + cloud_app_ids
            resource_key = 'application'
        
        # Generate permutations (identical set for each user)
        base_permutations = []
        for auth_flow, client_app, location, resource in product(
            auth_flows, client_app_types, locations, resources
        ):
            perm = {
                'authFlow': auth_flow,
                'clientAppType': client_app,
                'location': location,
                resource_key: resource
            }
            base_permutations.append(perm)
        
        # Build universal permutation (always first)
        universal_perm = {
            'authFlow': 'none',
            'clientAppType': 'all',
            'location': 'All',
            resource_key: resources[0] if resources else 'All'
        }
        
        # Ensure universal is first in the list
        base_permutations = [universal_perm] + [p for p in base_permutations if p != universal_perm]
        
        # Create per-user permutation sets (add user ID to each)
        user_permutations = {}
        for user_id in user_ids:
            user_perms = []
            for perm in base_permutations:
                user_perm = {'user': user_id, **perm}
                user_perms.append(user_perm)
            user_permutations[user_id] = user_perms
        
        return user_permutations
    
    def generate_permutations_for_guests(
        self,
        guest_user_ids: List[str],
        target_resource: str,
        named_locations: List[Dict],
        internal_guest_ids: Set[str] = None
    ) -> Dict[str, List[Dict]]:
        """Generate permutations for guests workflow.
        
        For each guest user, generates permutations following the pattern:
        clientAppType * authFlow * location * (application OR userAction)
        
        Same as users workflow but uses 'guest' key instead of 'user' for clarity.
        
        For user-actions target with device registration (registerOrJoinDevices),
        only generates permutations for internal guests (local guests) as other
        guest types can only register devices in their home tenant.
        
        Parameters:
            guest_user_ids (List[str]): List of guest user IDs to generate permutations for
            target_resource (str): Target resource type ('cloud-apps', 'user-actions', 'agent-resources')
            named_locations (List[Dict]): List of named location objects
            internal_guest_ids (Set[str], optional): Set of internal guest IDs for filtering device registration
        
        Returns:
            Dict[str, List[Dict]]: Map of guest_id -> list of permutation dicts
        """
        # Build dimension value sets
        # Authentication flows: static set
        auth_flows = ['none', 'deviceCodeFlow', 'authenticationTransfer']
        
        # Client application types: static set
        client_app_types = ['all', 'browser', 'mobileAppsAndDesktopClients', 
                           'exchangeActiveSync', 'other']
        
        # Locations: 'All', 'AllTrusted', plus all named locations
        locations = ['All', 'AllTrusted']
        for loc in named_locations:
            locations.append(loc.get('id'))
        
        # Resource dimension resolved on-demand based on target
        if target_resource == 'user-actions':
            resources = ['registerSecurityInformation', 'registerOrJoinDevices']
            resource_key = 'userAction'
        elif target_resource == 'agent-resources':
            agent_resource_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'agent-resources.json'
            )
            resources = ['AllAgentIdResources'] + agent_resource_ids
            resource_key = 'application'
        else:  # cloud-apps
            cloud_app_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'applications.json'
            )
            resources = ['All'] + cloud_app_ids
            resource_key = 'application'
        
        # Generate permutations (identical set for each guest)
        base_permutations = []
        for auth_flow, client_app, location, resource in product(
            auth_flows, client_app_types, locations, resources
        ):
            perm = {
                'authFlow': auth_flow,
                'clientAppType': client_app,
                'location': location,
                resource_key: resource
            }
            base_permutations.append(perm)
        
        # Build universal permutation (always first)
        universal_perm = {
            'authFlow': 'none',
            'clientAppType': 'all',
            'location': 'All',
            resource_key: resources[0] if resources else 'All'
        }
        
        # Ensure universal is first in the list
        base_permutations = [universal_perm] + [p for p in base_permutations if p != universal_perm]
        
        # Create per-guest permutation sets (add guest ID to each)
        guest_permutations = {}
        for guest_id in guest_user_ids:
            guest_perms = []
            for perm in base_permutations:
                # For device registration with user-actions, only include internal guests
                if (target_resource == 'user-actions' and 
                    perm.get('userAction') == 'registerOrJoinDevices' and 
                    internal_guest_ids is not None and 
                    guest_id not in internal_guest_ids):
                    # Skip device registration for non-internal guests
                    continue
                
                guest_perm = {'guests': guest_id, **perm}
                guest_perms.append(guest_perm)
            guest_permutations[guest_id] = guest_perms
        
        return guest_permutations
    
    def generate_permutations_for_agents(
        self,
        agent_ids: List[str],
        target_resource: str
    ) -> Dict[str, List[Dict]]:
        """Generate permutations for agent-identities workflow.
        
        For each agent, generates permutations following the pattern:
        application only (agents don't support conditions)
        
        Parameters:
            agent_ids (List[str]): List of agent identity IDs
            target_resource (str): Target resource type ('cloud-apps', 'agent-resources')
        
        Returns:
            Dict[str, List[Dict]]: Map of agent_id -> list of permutation dicts
        """
        # Resource dimension resolved on-demand based on target
        if target_resource == 'agent-resources':
            agent_resource_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'agent-resources.json'
            )
            resources = ['AllAgentIdResources'] + agent_resource_ids
        else:  # cloud-apps
            cloud_app_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'applications.json'
            )
            resources = ['All'] + cloud_app_ids
        
        # Build universal permutation (always first)
        universal_perm = {'application': resources[0] if resources else 'All'}
        
        # Generate base permutations
        base_permutations = [universal_perm]
        for resource in resources:
            if resource != universal_perm['application']:
                base_permutations.append({'application': resource})
        
        # Create per-agent permutation sets
        agent_permutations = {}
        for agent_id in agent_ids:
            agent_perms = []
            for perm in base_permutations:
                agent_perm = {'agent': agent_id, **perm}
                agent_perms.append(agent_perm)
            agent_permutations[agent_id] = agent_perms
        
        return agent_permutations
    
    def generate_permutations_for_workloads(
        self,
        workload_ids: List[str],
        target_resource: str,
        named_locations: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Generate permutations for workload-identities workflow.
        
        For each workload, generates permutations following the pattern:
        location * application
        
        Parameters:
            workload_ids (List[str]): List of workload identity IDs
            target_resource (str): Target resource type ('cloud-apps', 'agent-resources')
            named_locations (List[Dict]): List of named location objects
        
        Returns:
            Dict[str, List[Dict]]: Map of workload_id -> list of permutation dicts
        """
        # Locations: 'All', 'AllTrusted', plus all named locations
        locations = ['All', 'AllTrusted']
        for loc in named_locations:
            locations.append(loc.get('id'))
        
        # Resource dimension resolved on-demand based on target
        if target_resource == 'agent-resources':
            agent_resource_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'agent-resources.json'
            )
            resources = ['AllAgentIdResources'] + agent_resource_ids
        else:  # cloud-apps
            cloud_app_ids = self._load_resource_ids_from_cache(
                Path('cache') / 'policies' / 'applications.json'
            )
            resources = ['All'] + cloud_app_ids
        
        # Build universal permutation (always first)
        universal_perm = {
            'location': 'All',
            'application': resources[0] if resources else 'All'
        }
        
        # Generate base permutations
        base_permutations = [universal_perm]
        for location, resource in product(locations, resources):
            perm = {'location': location, 'application': resource}
            if perm != universal_perm:
                base_permutations.append(perm)
        
        # Create per-workload permutation sets
        workload_permutations = {}
        for workload_id in workload_ids:
            workload_perms = []
            for perm in base_permutations:
                workload_perm = {'workload': workload_id, **perm}
                workload_perms.append(workload_perm)
            workload_permutations[workload_id] = workload_perms
        
        return workload_permutations

    def extract_applications_from_policies(self, policies: List[Dict]) -> Set[str]:
        """Extract all application IDs mentioned in policies.
        
        Parameters:
            policies (List[Dict]): List of policy objects
        
        Returns:
            Set[str]: Set of application IDs
        """
        apps = set()
        
        for policy in policies:
            conditions = policy.get('conditions', {})
            applications = conditions.get('applications', {})
            
            # Include applications
            include_apps = applications.get('includeApplications', [])
            for app in include_apps:
                if app not in ['All', 'None']:
                    apps.add(app)
            
            # Exclude applications
            exclude_apps = applications.get('excludeApplications', [])
            for app in exclude_apps:
                if app not in ['All', 'None']:
                    apps.add(app)
        
        return apps

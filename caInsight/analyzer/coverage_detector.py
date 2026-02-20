"""
Universal coverage detector - identifies identities covered by universal policies.

This module detects which identities are protected by universal MFA, Auth Strength,
and blocking policies. Universal policies are those that apply to all resources with
no additional conditions, providing baseline protection.
"""

from typing import Dict, List, Set, Tuple


class CoverageDetector:
    """Detects universal policy coverage for identities"""
    
    @staticmethod
    def detect_universal_coverage_for_users(
        policies: List[Dict], 
        target_resource: str
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Detect universal MFA, Auth Strength, and blocking coverage for users.
        
        Parameters:
            policies (List[Dict]): Flattened policies
            target_resource (str): Target resource type ('cloud-apps', 'user-actions', 'agent-resources')
        
        Returns:
            Tuple[Set[str], Set[str], Set[str]]: Three sets:
                - Set of user IDs covered by universal MFA policies
                - Set of user IDs covered by universal Auth Strength policies
                - Set of user IDs covered by universal blocking policies
        """
        mfa_covered = set()
        auth_strength_covered = set()
        block_covered = set()
        
        for policy in policies:            
            # Check if this is a universal policy for the target resource
            if not CoverageDetector._is_universal_policy_for_users(policy, target_resource):
                continue
            
            # Extract covered users from includeUsers
            conditions = policy.get('conditions', {})
            users_section = conditions.get('users', {})
            include_users = users_section.get('includeUsers', [])
            exclude_users = users_section.get('excludeUsers', [])
            
            # Determine coverage based on grant controls
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            auth_strength = grant_controls.get('authenticationStrength', {})
            n_control_alternatives = len(built_in_controls) + (1 if auth_strength else 0)
            operator = grant_controls.get('operator')

            is_mfa_policy = 'mfa' in built_in_controls
            is_mfa_policy_or_with_one_control = is_mfa_policy and operator == 'OR' and n_control_alternatives == 1
            is_mfa_policy_and = is_mfa_policy and operator == 'AND'

            is_auth_strength_policy_or_with_one_control = auth_strength and operator == 'OR' and n_control_alternatives == 1
            is_auth_strength_policy_and = auth_strength and operator == 'AND'

            # Check for blocking policy
            if 'block' in built_in_controls:
                # Keep only users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                block_covered.update(covered_users)
            
            # Check for MFA policy
            elif is_mfa_policy_or_with_one_control or is_mfa_policy_and:
                # Keep only users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                mfa_covered.update(covered_users)
            
            # Check for Auth Strength policy
            elif is_auth_strength_policy_or_with_one_control or is_auth_strength_policy_and:
                # Keep only users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                auth_strength_covered.update(covered_users)
        
        return mfa_covered, auth_strength_covered, block_covered
    
    @staticmethod
    def detect_universal_coverage_for_guests(
        policies: List[Dict], 
        target_resource: str
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Detect universal MFA, Auth Strength, and blocking coverage for guest users.
        
        Parameters:
            policies (List[Dict]): Flattened policies
            target_resource (str): Target resource type ('cloud-apps', 'user-actions', 'agent-resources')
        
        Returns:
            Tuple[Set[str], Set[str], Set[str]]: Three sets:
                - Set of guest user IDs covered by universal MFA policies
                - Set of guest user IDs covered by universal Auth Strength policies
                - Set of guest user IDs covered by universal blocking policies
        """
        mfa_covered = set()
        auth_strength_covered = set()
        block_covered = set()
        
        for policy in policies:            
            # Check if this is a universal policy for the target resource
            if not CoverageDetector._is_universal_policy_for_guests(policy, target_resource):
                continue
            
            # Extract covered guest users from includeUsers
            conditions = policy.get('conditions', {})
            users_section = conditions.get('users', {})
            include_users = users_section.get('includeUsers', [])
            exclude_users = users_section.get('excludeUsers', [])
            
            # Determine coverage based on grant controls
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            auth_strength = grant_controls.get('authenticationStrength', {})
            n_control_alternatives = len(built_in_controls) + (1 if auth_strength else 0)
            operator = grant_controls.get('operator')

            is_mfa_policy = 'mfa' in built_in_controls
            is_mfa_policy_or_with_one_control = is_mfa_policy and operator == 'OR' and n_control_alternatives == 1
            is_mfa_policy_and = is_mfa_policy and operator == 'AND'

            is_auth_strength_policy_or_with_one_control = auth_strength and operator == 'OR' and n_control_alternatives == 1
            is_auth_strength_policy_and = auth_strength and operator == 'AND'

            # Check for blocking policy
            if 'block' in built_in_controls:
                # Keep only guest users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                block_covered.update(covered_users)
            
            # Check for MFA policy
            elif is_mfa_policy_or_with_one_control or is_mfa_policy_and:
                # Keep only guest users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                mfa_covered.update(covered_users)
            
            # Check for Auth Strength policy
            elif is_auth_strength_policy_or_with_one_control or is_auth_strength_policy_and:
                # Keep only guest users that are included and not excluded
                covered_users = CoverageDetector._apply_include_exclude(include_users, exclude_users)
                auth_strength_covered.update(covered_users)
        
        return mfa_covered, auth_strength_covered, block_covered
    
    @staticmethod
    def detect_universal_coverage_for_agents(
        policies: List[Dict],
        target_resource: str
    ) -> Set[str]:
        """Detect universal blocking coverage for agent identities.
        
        Note: Agent identities only support blocking policies (no MFA/Auth Strength).
        
        Parameters:
            policies (List[Dict]): Flattened policies (from flat_policies_agent_identities.json)
            target_resource (str): Target resource type ('cloud-apps', 'agent-resources')
        
        Returns:
            Set[str]: Set of agent identity IDs covered by universal blocking policies
        """
        block_covered = set()
        
        for policy in policies:
            # Check if this is a universal policy for the target resource
            if not CoverageDetector._is_universal_policy_for_agents(policy, target_resource):
                continue
            
            # Extract covered agents from clientApplications section
            conditions = policy.get('conditions', {})
            client_apps = conditions.get('clientApplications', {})
            include_agents = client_apps.get('includeAgentIdServicePrincipals', [])
            exclude_agents = client_apps.get('excludeAgentIdServicePrincipals', [])
            
            # Check for blocking policy
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            
            if 'block' in built_in_controls:
                covered_agents = CoverageDetector._apply_include_exclude(include_agents, exclude_agents)
                block_covered.update(covered_agents)
        
        return block_covered
    
    @staticmethod
    def detect_universal_coverage_for_workloads(
        policies: List[Dict],
        target_resource: str
    ) -> Set[str]:
        """Detect universal blocking coverage for workload identities.
        
        Note: Workload identities only support blocking policies (no MFA/Auth Strength).
        
        Parameters:
            policies (List[Dict]): Flattened policies (from flat_policies_workload_identities.json)
            target_resource (str): Target resource type ('cloud-apps', 'agent-resources')
        
        Returns:
            Set[str]: Set of workload identity IDs covered by universal blocking policies
        """
        block_covered = set()
        
        for policy in policies:
            # Check if this is a universal policy for the target resource

            if not CoverageDetector._is_universal_policy_for_workloads(policy, target_resource):
                continue
            
            # Extract covered workloads from clientApplications section
            conditions = policy.get('conditions', {})
            client_apps = conditions.get('clientApplications', {})
            include_workloads = client_apps.get('includeServicePrincipals', [])
            exclude_workloads = client_apps.get('excludeServicePrincipals', [])
            
            # Check for blocking policy
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            
            if 'block' in built_in_controls:
                covered_workloads = CoverageDetector._apply_include_exclude(include_workloads, exclude_workloads)
                block_covered.update(covered_workloads)
        
        return block_covered
    
    @staticmethod
    def _is_universal_policy_for_users(policy: Dict, target_resource: str) -> bool:
        """Check if a policy is a universal policy for users (no conditions).
        
        Parameters:
            policy (Dict): Policy object
            target_resource (str): Target resource type
        
        Returns:
            bool: True if this is a universal policy
        """
        conditions = policy.get('conditions', {})
        
        # Check resource targeting based on target_resource
        apps = conditions.get('applications', {})
        include_apps = apps.get('includeApplications', [])
        exclude_apps = apps.get('excludeApplications', [])
        include_actions = apps.get('includeUserActions', [])
        
        if target_resource == 'cloud-apps':
            # Must target All cloud apps
            if 'All' not in include_apps or exclude_apps:
                return False
        elif target_resource == 'user-actions':
            # Must target registerSecurityInformation or registerOrJoinDevices or both
            valid_actions = {'urn:user:registersecurityinfo', 'urn:user:registerdevice'}
            if not set(include_actions).issubset(valid_actions):
                return False
        elif target_resource == 'agent-resources':
            # Must target AllAgentIdResources
            if 'AllAgentIdResources' not in include_apps:
                return False
        else:
            return False
        
        # Check for the absence of conditions
        platforms = conditions.get('platforms', {})
        if platforms and platforms.get('includePlatforms'):
            return False
        
        client_app_types = conditions.get('clientAppTypes', [])
        if client_app_types and client_app_types != ['all']:
            return False
        
        locations = conditions.get('locations', {})
        if locations and (locations.get('excludeLocations') or 
                          (locations.get('includeLocations') and locations.get('includeLocations') != ['All'])):
            return False
        
        auth_flows = conditions.get('authenticationFlows', {})
        if auth_flows and auth_flows.get('transferMethods'):
            transfer_methods = auth_flows.get('transferMethods', [])
            if transfer_methods and transfer_methods != ['none']:
                return False
        
        return True
    
    @staticmethod
    def _is_universal_policy_for_guests(policy: Dict, target_resource: str) -> bool:
        """Check if a policy is a universal policy for guest users (no conditions).
        
        Parameters:
            policy (Dict): Policy object
            target_resource (str): Target resource type
        
        Returns:
            bool: True if this is a universal policy for guests
        """
        conditions = policy.get('conditions', {})
        
        # Check resource targeting based on target_resource
        apps = conditions.get('applications', {})
        include_apps = apps.get('includeApplications', [])
        exclude_apps = apps.get('excludeApplications', [])
        include_actions = apps.get('includeUserActions', [])
        
        if target_resource == 'cloud-apps':
            # Must target All cloud apps
            if 'All' not in include_apps or exclude_apps:
                return False
        elif target_resource == 'user-actions':
            # Must target registerSecurityInformation or registerOrJoinDevices or both
            valid_actions = {'urn:user:registersecurityinfo', 'urn:user:registerdevice'}
            if not set(include_actions).issubset(valid_actions):
                return False
        elif target_resource == 'agent-resources':
            # Must target AllAgentIdResources
            if 'AllAgentIdResources' not in include_apps:
                return False
        else:
            return False
        
        # Check for the absence of conditions (same logic as users)
        platforms = conditions.get('platforms', {})
        if platforms and platforms.get('includePlatforms'):
            return False
        
        client_app_types = conditions.get('clientAppTypes', [])
        if client_app_types and client_app_types != ['all']:
            return False
        
        locations = conditions.get('locations', {})
        if locations and (locations.get('excludeLocations') or 
                          (locations.get('includeLocations') and locations.get('includeLocations') != ['All'])):
            return False
        
        auth_flows = conditions.get('authenticationFlows', {})
        if auth_flows and auth_flows.get('transferMethods'):
            transfer_methods = auth_flows.get('transferMethods', [])
            if transfer_methods and transfer_methods != ['none']:
                return False
        
        return True
    
    @staticmethod
    def _is_universal_policy_for_agents(policy: Dict, target_resource: str) -> bool:
        """Check if a policy is a universal policy for agent identities.

        Note: Agent identities don't support conditions beyond resource targeting.
        
        Parameters:
            policy (Dict): Policy object
            target_resource (str): Target resource type
        
        Returns:
            bool: True if this is a universal policy
        """
        conditions = policy.get('conditions', {})
        
        # Check resource targeting
        apps = conditions.get('applications', {})
        include_apps = apps.get('includeApplications', [])
        
        if target_resource == 'cloud-apps':
            if 'All' not in include_apps:
                return False
        elif target_resource == 'agent-resources':
            if 'AllAgentIdResources' not in include_apps:
                return False
        else:
            return False

        # Agent identities don't support conditions beyond resource targeting       

        return True
    
    @staticmethod
    def _is_universal_policy_for_workloads(policy: Dict, target_resource: str) -> bool:
        """Check if a policy is a universal policy for workload identities.

        Note: Workload identities only support the locations condition beyond resource targeting.
        
        Parameters:
            policy (Dict): Policy object
            target_resource (str): Target resource type
        
        Returns:
            bool: True if this is a universal policy
        """
        conditions = policy.get('conditions', {})
        
        # Check resource targeting
        apps = conditions.get('applications', {})
        include_apps = apps.get('includeApplications', [])
        
        if target_resource == 'cloud-apps':
            if 'All' not in include_apps:
                return False
        elif target_resource == 'agent-resources':
            if 'AllAgentIdResources' not in include_apps:
                return False
        else:
            return False
        
        # Workload identities only support the locations condition beyond resource targeting
        locations = conditions.get('locations', {})
        if locations and (locations.get('excludeLocations') or 
                          (locations.get('includeLocations') and locations.get('includeLocations') != ['All'])):
            return False
        
        return True
    
    @staticmethod
    def detect_user_action_coverage_for_guests(policies: List[Dict]) -> Dict[str, bool]:
        """Detect which user actions have universal coverage for guests.
        
        This method checks if there are universal policies that cover each user action
        for guest users. It's used in critical gap scenarios to determine which specific
        user actions need gap reports.
        
        Parameters:
            policies (List[Dict]): Flattened policies (can be empty list)
        
        Returns:
            Dict[str, bool]: Dictionary mapping user action URIs to coverage status:
                - 'urn:user:registersecurityinfo': True if covered, False otherwise
                - 'urn:user:registerdevice': True if covered, False otherwise
        """
        # Initialize coverage status for both user actions
        action_coverage = {
            'urn:user:registersecurityinfo': False,
            'urn:user:registerdevice': False
        }
        
        # If no policies, return all uncovered
        if not policies:
            return action_coverage
        
        # Check each policy for user action coverage
        for policy in policies:
            conditions = policy.get('conditions', {})
            apps = conditions.get('applications', {})
            include_actions = apps.get('includeUserActions', [])
            
            # Skip policies that don't target user actions
            if not include_actions:
                continue
            
            # Check if policy has strong controls
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            auth_strength = grant_controls.get('authenticationStrength', {})
            
            has_strong_control = ('block' in built_in_controls or 
                                 'mfa' in built_in_controls or 
                                 auth_strength)
            
            if not has_strong_control:
                continue
            
            # Check if policy is universal (no limiting conditions)
            is_universal = CoverageDetector._is_universal_policy_for_guests(policy, 'user-actions')
            
            if not is_universal:
                continue
            
            # Check which user actions are covered by this policy
            for action_uri in include_actions:
                if action_uri.lower() == 'urn:user:registersecurityinfo':
                    action_coverage['urn:user:registersecurityinfo'] = True
                elif action_uri.lower() == 'urn:user:registerdevice':
                    action_coverage['urn:user:registerdevice'] = True
        
        return action_coverage
    
    @staticmethod
    def _apply_include_exclude(include_list: List[str], exclude_list: List[str]) -> Set[str]:
        """Apply include/exclude logic to get net covered identities.
        
        Parameters:
            include_list (List[str]): List of included identity IDs
            exclude_list (List[str]): List of excluded identity IDs
        
        Returns:
            Set[str]: Set of net covered identity IDs (includes minus excludes)
        """
        included = set(include_list) if include_list else set()
        excluded = set(exclude_list) if exclude_list else set()
        
        # Remove excluded from included
        covered = included - excluded
        
        return covered

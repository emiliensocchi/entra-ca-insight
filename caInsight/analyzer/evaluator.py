"""
Policy evaluation logic for gap analysis.

This module evaluates per-identity permutation sets against flattened policies
to identify gaps in conditional access coverage. Supports early termination
for efficient analysis of well-protected identities.
"""

import math
from typing import List, Dict, Any, Optional


class PolicyEvaluator:
    """Evaluates policies against permutations to find gaps"""
    
    def __init__(self, object_map: Dict[str, Any] = None):
        """Initialize the policy evaluator.
        
        Parameters:
            object_map (Dict[str, Any], optional): Mapping of group membership links
                                                  in format 'groupId:memberId' for
                                                  resolving transitive group membership.
                                                  Default is None.
        """
        # Convert to set for O(1) lookup performance
        if object_map and isinstance(object_map, list):
            self.object_map = set(object_map)
        elif object_map:
            self.object_map = object_map
        else:
            self.object_map = set()
    
    def evaluate_identity_permutations(
        self, 
        identity_id: str,
        identity_type: str,
        permutations: List[Dict],
        flattened_policies: List[Dict],
        early_termination_pct: Optional[int] = 100
    ) -> Dict:
        """Evaluate permutations for a single identity against flattened policies.
        
        This is the core evaluation method that:
        1. Evaluates universal permutation first (fastest gap detection)
        2. Checks each permutation against all flattened policies
        3. Stops early if identity is clearly protected (early termination)
        4. Returns gaps and evaluation statistics
        
        Args:
            identity_id: The identity ID (user, agent, or workload identity)
            identity_type: Type of identity ('users', 'agents', 'workloadIdentities')
            permutations: List of permutation dicts for this identity
            flattened_policies: List of flattened policy dicts (groups/roles resolved to member IDs)
            early_termination_pct: Percentage (0-100) to stop if no gaps found. 100 = evaluate all.
        
        Returns:
            Dict with:
                - identity_id: str
                - identity_type: str
                - is_protected: bool (True if no gaps or early terminated without gaps)
                - gaps: List[Dict] (permutations that matched no policy)
                - evaluated_count: int (number of permutations evaluated)
                - total_count: int (total permutations)
                - early_terminated: bool (True if stopped early)
                - termination_reason: Optional[str] (reason for early termination)
        """
        if not permutations:
            return {
                'identity_id': identity_id,
                'identity_type': identity_type,
                'is_protected': True,
                'gaps': [],
                'evaluated_count': 0,
                'total_count': 0,
                'early_terminated': False,
                'termination_reason': None
            }
        
        gaps = []
        evaluated_count = 0
        total_count = len(permutations)
        early_terminated = False
        termination_reason = None
        
        # Calculate early termination threshold
        if early_termination_pct < 100:
            early_term_threshold = math.ceil(total_count * (early_termination_pct / 100.0))
        else:
            early_term_threshold = total_count
        
        # Evaluate permutations sequentially
        for perm in permutations:
            evaluated_count += 1
            
            # Check if this permutation is covered by any policy
            is_covered = self._is_permutation_covered(perm, identity_id, identity_type, flattened_policies)
            
            if not is_covered:
                # Gap found - add to results
                gaps.append(perm)
            
            # Check early termination condition
            if evaluated_count >= early_term_threshold and early_termination_pct < 100:
                if not gaps:
                    # No gaps found after XX% - identity is protected
                    early_terminated = True
                    termination_reason = f"No gaps found after evaluating {early_termination_pct}% ({evaluated_count}/{total_count}) of permutations"
                    break
        
        # Consolidate dimension-level gaps to avoid redundant gaps or incorrect "all" gaps covered individually
        # E.g. "All" locations are not covered, but each location is individually covered by a policy -> remove "All" gap
        # E.g. "All" locations are not covered and each individual location is also not covered -> consolidate to a single "All" gap
        gaps = self._consolidate_dimension_gaps(gaps, permutations, identity_type)
        
        # Filter to universal gap only if one exists (all other gaps become redundant)
        gaps = self._filter_to_universal_gap_if_exists(gaps, identity_type)
        
        # Determine protection status
        is_protected = len(gaps) == 0
        
        return {
            'identity_id': identity_id,
            'identity_type': identity_type,
            'is_protected': is_protected,
            'gaps': gaps,
            'evaluated_count': evaluated_count,
            'total_count': total_count,
            'early_terminated': early_terminated,
            'termination_reason': termination_reason
        }
    
    def _is_permutation_covered(
        self, 
        permutation: Dict, 
        identity_id: str,
        identity_type: str,
        flattened_policies: List[Dict]
    ) -> bool:
        """Check if a permutation is covered by any flattened policy.
        
        A permutation is covered if:
        1. Identity is in includeUsers/includeAgents/includeWorkloads (after flattening)
        2. NOT in excludeUsers/excludeAgents/excludeWorkloads
        3. All permutation conditions match policy conditions
        4. Policy has required grant controls (MFA/Auth Strength/Block)
        
        Args:
            permutation: Permutation dict with identity and condition values
            identity_id: The identity ID being evaluated
            identity_type: Type of identity ('users', 'agents', 'workloadIdentities')
            flattened_policies: List of flattened policies
        
        Returns:
            bool: True if permutation is covered by at least one policy
        """
        for policy in flattened_policies:
            if self._policy_covers_permutation(policy, permutation, identity_id, identity_type):
                return True
        
        return False
    
    def _policy_covers_permutation(
        self,
        policy: Dict,
        permutation: Dict,
        identity_id: str,
        identity_type: str
    ) -> bool:
        """Check if a single policy covers a permutation.
        
        Args:
            policy: Flattened policy dict
            permutation: Permutation dict
            identity_id: Identity ID
            identity_type: Identity type
        
        Returns:
            bool: True if policy covers this permutation
        """
        conditions = policy.get('conditions', {})
        
        # Step 1: Check identity assignment
        if not self._identity_matches_policy(policy, identity_id, identity_type):
            return False
        
        # Step 2: Check application/resource matching
        if not self._application_matches(conditions, permutation, identity_type):
            return False
        
        # Step 3: Check condition matching (clientAppType, location, platform, authFlow)
        if not self._conditions_match(conditions, permutation, identity_type):
            return False
        
        # Step 4: Check grant controls (must have MFA, Auth Strength, or Block)
        if not self._has_required_controls(policy):
            return False
        
        return True
    
    def _identity_matches_policy(
        self, 
        policy: Dict, 
        identity_id: str, 
        identity_type: str
    ) -> bool:
        """Check if identity matches policy's user/agent/workload conditions.
        
        In flattened policies:
        - includeUsers contains all resolved user IDs (from groups/roles)
        - excludeUsers contains all resolved user IDs to exclude
        - Similar for agents/workloads in clientApplications section
        
        Args:
            policy: Flattened policy dict
            identity_id: Identity ID to check
            identity_type: 'users', 'guests', 'agents', or 'workloadIdentities'
        
        Returns:
            bool: True if identity is included and not excluded
        """
        conditions = policy.get('conditions', {})
        
        if identity_type in ['users', 'guests']:
            # Both users and guests are resolved to user IDs in includeUsers/excludeUsers
            users = conditions.get('users', {})
            include_users = users.get('includeUsers', [])
            exclude_users = users.get('excludeUsers', [])
            
            # Check if included
            if 'All' not in include_users and identity_id not in include_users:
                return False
            
            # Check if excluded
            if 'All' in exclude_users or identity_id in exclude_users:
                return False
            
            return True
        
        elif identity_type in ['agents', 'workloadIdentities']:
            # For agents/workloads, check clientApplications section
            client_apps = conditions.get('clientApplications', {})
            
            if identity_type == 'agents':
                include_field = 'includeServicePrincipals'  # Agents use service principals
                exclude_field = 'excludeServicePrincipals'
            else:  # workloadIdentities
                include_field = 'includeServicePrincipals'
                exclude_field = 'excludeServicePrincipals'
            
            include_ids = client_apps.get(include_field, [])
            exclude_ids = client_apps.get(exclude_field, [])
            
            # Check if included
            if 'All' not in include_ids and identity_id not in include_ids:
                return False
            
            # Check if excluded
            if 'All' in exclude_ids or identity_id in exclude_ids:
                return False
            
            return True
        
        return False
    
    def _application_matches(
        self, 
        conditions: Dict, 
        permutation: Dict, 
        identity_type: str
    ) -> bool:
        """Check if permutation's application matches policy's application conditions.
        
        Args:
            conditions: Policy conditions dict
            permutation: Permutation dict
            identity_type: Identity type
        
        Returns:
            bool: True if application matches
        """
        applications = conditions.get('applications', {})
        
        # Get permutation's application (handle both 'user' and 'guest' identity types)
        perm_app = permutation.get('application')
        perm_user_action = permutation.get('userAction')
        
        # Check includeApplications
        include_apps = applications.get('includeApplications', [])
        include_user_actions = applications.get('includeUserActions', [])
        
        # For user actions workflow
        if perm_user_action:
            if include_user_actions and perm_user_action not in include_user_actions:
                return False
        # For cloud-apps/agent-resources workflow
        elif perm_app:
            if 'All' not in include_apps and perm_app not in include_apps:
                return False
        
        # Check excludeApplications
        exclude_apps = applications.get('excludeApplications', [])
        if perm_app and ('All' in exclude_apps or perm_app in exclude_apps):
            return False
        
        return True
    
    def _conditions_match(
        self, 
        conditions: Dict, 
        permutation: Dict, 
        identity_type: str
    ) -> bool:
        """Check if all permutation conditions match policy conditions.
        
        Conditions to check (based on identity type):
        - Users: clientAppType, authFlow, location, platforms
        - Agents: none (agents don't support conditions reliably)
        - Workloads: location only
        
        Args:
            conditions: Policy conditions dict
            permutation: Permutation dict
            identity_type: Identity type
        
        Returns:
            bool: True if all conditions match
        """
        # Agent identities don't support conditions
        if identity_type == 'agents':
            return True
        
        # Check location (users and workloads)
        if not self._location_matches(conditions, permutation):
            return False
        
        # Users have additional conditions
        if identity_type == 'users':
            if not self._client_app_type_matches(conditions, permutation):
                return False
            
            if not self._auth_flow_matches(conditions, permutation):
                return False
            
        return True
    
    def _location_matches(self, conditions: Dict, permutation: Dict) -> bool:
        """Check if location condition matches."""
        perm_location = permutation.get('location')
        if not perm_location:
            return True  # No location in permutation means no restriction
        
        locations = conditions.get('locations', {})
        if not locations:
            return True  # Policy doesn't restrict locations
        
        include_locs = locations.get('includeLocations', [])
        exclude_locs = locations.get('excludeLocations', [])
        
        # Check include
        if include_locs and 'All' not in include_locs and perm_location not in include_locs:
            # Special case: AllTrusted might cover named locations
            if perm_location != 'AllTrusted' or 'AllTrusted' not in include_locs:
                return False
        
        # Check exclude
        if exclude_locs and ('All' in exclude_locs or perm_location in exclude_locs):
            return False
        
        return True
    
    def _client_app_type_matches(self, conditions: Dict, permutation: Dict) -> bool:
        """Check if clientAppType condition matches."""
        perm_cat = permutation.get('clientAppType')
        if not perm_cat or perm_cat == 'all':
            return True
        
        policy_cats = conditions.get('clientAppTypes', [])
        if not policy_cats:
            return True  # Policy doesn't restrict client app types
        
        # Check if permutation's type is in policy's list or 'all' is in policy
        if 'all' in policy_cats or perm_cat in policy_cats:
            return True
        
        return False
    
    def _auth_flow_matches(self, conditions: Dict, permutation: Dict) -> bool:
        """Check if authFlow condition matches."""
        perm_flow = permutation.get('authFlow')
        if not perm_flow or perm_flow == 'none':
            return True
        
        auth_flows = conditions.get('authenticationFlows', {})
        if not auth_flows:
            return True  # Policy doesn't restrict auth flows
        
        transfer_methods = auth_flows.get('transferMethods', [])
        if not transfer_methods or 'none' in transfer_methods:
            return True
        
        # Check if permutation's flow matches
        if perm_flow in transfer_methods:
            return True
        
        return False
    
    def _has_required_controls(self, policy: Dict) -> bool:
        """Check if policy has required grant controls (MFA, Auth Strength, or Block).
        
        Args:
            policy: Policy dict
        
        Returns:
            bool: True if policy has MFA, Authentication Strength, or Block control
        """
        grant_controls = policy.get('grantControls', {})
        
        # Check for Block
        if grant_controls.get('operator') == 'OR' and grant_controls.get('builtInControls'):
            if 'block' in grant_controls['builtInControls']:
                return True
        
        # Check for MFA
        if grant_controls.get('builtInControls'):
            if 'mfa' in grant_controls['builtInControls']:
                return True
        
        # Check for Authentication Strength
        if grant_controls.get('authenticationStrength'):
            strength_id = grant_controls['authenticationStrength'].get('id')
            if strength_id:
                return True
        
        return False
    
    def _consolidate_dimension_gaps(
        self,
        gaps: List[Dict],
        all_permutations: List[Dict],
        identity_type: str
    ) -> List[Dict]:
        """Consolidate dimension-level gaps to avoid redundant reporting.
        
        Two consolidation scenarios:
        1. If ALL individual values of a dimension are gaps → replace with single "all" gap
        2. If "all" is a gap BUT individual values are covered → remove the false "all" gap
        
        Args:
            gaps: List of gap permutations
            all_permutations: Full list of permutations for this identity
            identity_type: Type of identity ('users', 'guests', 'agents', 'workloadIdentities')
        
        Returns:
            Consolidated list of gaps
        """
        if not gaps or not all_permutations:
            return gaps
        
        # Determine which dimensions to check based on identity type
        dimensions_to_check = []
        
        if identity_type in ['users', 'guests']:
            dimensions_to_check = ['location', 'clientAppType', 'authFlow']
            # Also check application or userAction
            if any('application' in p for p in all_permutations):
                dimensions_to_check.append('application')
            if any('userAction' in p for p in all_permutations):
                dimensions_to_check.append('userAction')
        elif identity_type == 'workloadIdentities':
            dimensions_to_check = ['location', 'application']
        elif identity_type == 'agents':
            dimensions_to_check = ['application']
        
        consolidated_gaps = list(gaps)  # Work with a copy
        
        for dimension in dimensions_to_check:
            # Extract all unique values for this dimension from all permutations
            all_values = set()
            for perm in all_permutations:
                value = perm.get(dimension)
                if value:
                    all_values.add(value)
            
            # Separate 'all'/'All' from individual values
            universal_values = {'all', 'All', 'AllTrusted', 'AllAgentIdResources', 'none'}
            individual_values = all_values - universal_values
            
            if not individual_values:
                continue  # No individual values to consolidate
            
            # Extract gap values for this dimension
            gap_values = set()
            for gap in consolidated_gaps:
                value = gap.get(dimension)
                if value:
                    gap_values.add(value)
            
            gap_individual_values = gap_values - universal_values
            gap_universal_values = gap_values & universal_values
            
            # Situation 1: ALL individual values are gaps → consolidate to "all"
            if gap_individual_values == individual_values and len(individual_values) > 1:
                # Remove all individual gap entries for this dimension
                consolidated_gaps = [
                    g for g in consolidated_gaps 
                    if g.get(dimension) not in individual_values
                ]
                
                # Add single universal gap if not already present
                if not gap_universal_values:
                    # Create a universal gap based on the first individual gap
                    sample_gap = next((g for g in gaps if g.get(dimension) in individual_values), None)
                    if sample_gap:
                        universal_gap = sample_gap.copy()
                        # Replace dimension value with universal
                        if dimension == 'location':
                            universal_gap[dimension] = 'All'
                        elif dimension == 'clientAppType':
                            universal_gap[dimension] = 'all'
                        elif dimension == 'authFlow':
                            universal_gap[dimension] = 'none'
                        elif dimension == 'application':
                            universal_gap[dimension] = 'All'
                        elif dimension == 'userAction':
                            # User actions don't have an 'all' concept, skip consolidation
                            continue
                        
                        consolidated_gaps.append(universal_gap)
            
            # Situation 2: "all" is a gap BUT all individual values are covered
            elif gap_universal_values and not gap_individual_values:
                # Remove the incorrect "all" gap
                consolidated_gaps = [
                    g for g in consolidated_gaps 
                    if g.get(dimension) not in universal_values
                ]
        
        return consolidated_gaps
    
    def _filter_to_universal_gap_if_exists(
        self,
        gaps: List[Dict],
        identity_type: str
    ) -> List[Dict]:
        """Filter to only universal gap if one exists, as all other gaps become redundant.
        
        A universal gap is one where ALL dimensions are set to their universal values:
        - Users/Guests: location='All', clientAppType='all', authFlow='none', application='All'
        - Workloads: location='All', application='All'
        - Agents: application='All'
        
        If a universal gap exists, all specific gaps are redundant and should be removed.
        
        Args:
            gaps: List of gap permutations
            identity_type: Type of identity ('users', 'guests', 'agents', 'workloadIdentities')
        
        Returns:
            List containing only universal gap if one exists, otherwise all gaps
        """
        if not gaps:
            return gaps
        
        # Define universal values for each identity type
        if identity_type in ['users', 'guests']:
            # Check for universal gap in users/guests
            for gap in gaps:
                location = gap.get('location')
                client_app = gap.get('clientAppType')
                auth_flow = gap.get('authFlow')
                application = gap.get('application')
                user_action = gap.get('userAction')
                agent_resource = gap.get('agentResource')
                
                # Universal gap: All dimensions are universal values
                is_universal = (
                    location == 'All' and
                    client_app == 'all' and
                    auth_flow == 'none' and
                    (application == 'All' or user_action in ['registerSecurityInformation', 'registerOrJoinDevices'] or agent_resource == 'All')
                )
                
                if is_universal:
                    return [gap]  # Return only the universal gap
        
        elif identity_type == 'workloadIdentities':
            # Check for universal gap in workload identities
            for gap in gaps:
                location = gap.get('location')
                application = gap.get('application')
                
                # Universal gap: All dimensions are universal values
                is_universal = (
                    location == 'All' and
                    application == 'All'
                )
                
                if is_universal:
                    return [gap]  # Return only the universal gap
        
        elif identity_type == 'agents':
            # Check for universal gap in agents
            for gap in gaps:
                application = gap.get('application')
                
                # Universal gap: application is 'All'
                is_universal = (application == 'All')
                
                if is_universal:
                    return [gap]  # Return only the universal gap
        
        # No universal gap found, return all gaps
        return gaps
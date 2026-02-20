"""
Microsoft Graph API client for fetching policies and related data
"""

# Standard library imports
import json
import time
import urllib3
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple, Set, Callable

# Third-party imports
import requests


# Special Conditional Access keywords that should not be resolved as object IDs
SPECIAL_CA_VALUES = {'All', 'AllTrusted', 'GuestsOrExternalUsers', 'AllAgentIdResources', 'None', 'unknownFutureValue'}

class GraphAPIClient:
    """Client for Microsoft Graph API operations"""
    
    def __init__(self, token: str, proxy: str = None):
        """Initialize the Graph API client with an access token.
        
        Parameters:
            token (str): Microsoft Graph API access token with appropriate permissions
            proxy (str): Proxy address in format 'host:port' (e.g., '127.0.0.1:8080'). 
                        If provided, routes all requests through proxy without cert verification.
        """
        self.token = token
        self.msgraph_domain = "graph.microsoft.com"
        self.cache_dir = Path("cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Proxy configuration for debugging (e.g., Burp Suite)
        if proxy:
            self.proxies = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            self.verify_ssl = False
            # Suppress SSL warnings when using proxy
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            self.proxies = None
            self.verify_ssl = True
        
        # HTTP Session for connection pooling (reuse TCP connections)
        self.session = requests.Session()
        self.session.proxies = self.proxies
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })

    @staticmethod
    def _retry_on_failure(func: Callable, max_attempts: int = 3, delay: float = 1.0, skip_on_404: bool = True):
        """Execute a function with retry logic.
        
        Wraps a function call with retry logic that:
        - Retries up to max_attempts times
        - Skips retries on 404 errors (if skip_on_404 is True)
        - Adds delay between retry attempts
        - Re-raises the last exception if all retries fail
        
        Parameters:
            func (Callable): The function to execute (should return requests.Response)
            max_attempts (int): Maximum number of attempts (default: 3)
            delay (float): Delay in seconds between retries (default: 1.0)
            skip_on_404 (bool): If True, don't retry on 404 errors (default: True)
        
        Returns:
            requests.Response: The successful response
            
        Raises:
            Exception: The last exception encountered if all retries fail
        """
        last_exception = None
        
        for attempt in range(max_attempts):
            try:
                response = func()
                response.raise_for_status()
                return response
            except requests.exceptions.HTTPError as e:
                last_exception = e
                if skip_on_404 and e.response.status_code == 404:
                    # Resource doesn't exist, no point retrying
                    raise
                elif attempt < max_attempts - 1:
                    print(f"    HTTP error (attempt {attempt + 1}/{max_attempts}): {e.response.status_code}, retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    raise
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < max_attempts - 1:
                    print(f"    Request timed out (attempt {attempt + 1}/{max_attempts}), retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    raise
            except requests.exceptions.RequestException as e:
                last_exception = e
                if attempt < max_attempts - 1:
                    print(f"    Request failed (attempt {attempt + 1}/{max_attempts}): {type(e).__name__}, retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    raise
        
        # Should never reach here, but just in case
        if last_exception:
            raise last_exception

    def validate_token(self) -> tuple[bool, str]:
        """Validate the access token by making a test API call.
        
        Tests the token by attempting to access the /me endpoint. Provides
        detailed error messages for common token issues including invalid tokens,
        missing permissions, and network problems.
        
        Returns:
            tuple[bool, str]: A tuple containing:
                - bool: True if token is valid and has permissions, False otherwise
                - str: Error message if validation failed, empty string if successful
        """
        url = f"https://{self.msgraph_domain}/v1.0/me"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return False, "Invalid or expired access token. Please provide a valid Microsoft Graph access token."
            elif response.status_code == 403:
                return False, "Access token is valid but lacks required permissions. Ensure the token has Policy.Read.All or Policy.ReadWrite.ConditionalAccess permissions."
            elif response.status_code >= 400:
                return False, f"Token validation failed with status {response.status_code}: {response.text}"
            
            return True, ""
        except requests.exceptions.Timeout:
            return False, "Token validation timed out. Check your network connection."
        except requests.exceptions.RequestException as e:
            return False, f"Token validation failed: {str(e)}"

    def get_all_policies(self, use_cache: bool = True) -> List[Dict]:
        """Fetch all conditional access policies from Microsoft Graph API.
        
        Retrieves all conditional access policies (enabled and disabled) without
        any filtering. Useful for policy browsing and reporting where you want to
        see the complete picture of all policies in the tenant.
        Results are cached to improve performance on subsequent runs.
        
        Parameters:
            use_cache (bool): If True, return cached policies if available. If False,
                            fetch fresh data from the API. Default is True.
        
        Returns:
            List[Dict]: List of all conditional access policy objects
        
        Raises:
            ValueError: If token is invalid, expired, or lacks required permissions
        """
        cache_file = self.cache_dir / "policies" / "policies.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
                
        url = f"https://{self.msgraph_domain}/beta/identity/conditionalAccess/policies"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=10),
                skip_on_404=False  # Policy endpoint should exist
            )
            
            if response.status_code == 401:
                raise ValueError("Invalid or expired access token. Please provide a valid Microsoft Graph access token.")
            elif response.status_code == 403:
                raise ValueError("Access denied. The token lacks required permissions (Policy.Read.All or Policy.ReadWrite.ConditionalAccess).")
                
        except requests.exceptions.Timeout:
            raise ValueError("Request timed out while fetching policies after 3 attempts. Check your network connection.")
        except requests.exceptions.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ValueError("Invalid or expired access token. Please provide a valid Microsoft Graph access token.")
            raise
        
        data = response.json()
        policies = data.get('value', [])
        
        # Merge with existing cache (preserve any manually cached policies)
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    existing_policies = json.load(f)
                
                # Build set of existing policy IDs
                existing_ids = {p.get('id') for p in existing_policies if p.get('id')}
                
                # Add new policies that aren't already cached
                for policy in policies:
                    if policy.get('id') not in existing_ids:
                        existing_policies.append(policy)
                
                # Update cache with merged list
                policies = existing_policies
            except Exception as e:
                print(f"Warning: Could not merge policies cache: {e}")
        
        # Save merged policies cache
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(policies, f, indent=2)
            
        return policies

    def get_all_active_members(self, use_cache: bool = True) -> List[Dict]:
        """Get all active members in the tenant.
        
        Retrieves all active (accountEnabled=true) members from the tenant via MS Graph API,
        handling pagination automatically to ensure all users are returned.
        
        Parameters:
            use_cache (bool): If True, return cached members if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of active member objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-members.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        url = f"https://{self.msgraph_domain}/v1.0/users?$filter=accountEnabled eq true and userType eq 'Member'"
        url += "&$select=id,displayName,userPrincipalName,userType,identities"  # Select only relevant fields for members
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        users = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                users.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch users: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched users
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(users, f, indent=2)
        
        return users

    def get_all_active_guests(self, use_cache: bool = True) -> List[Dict]:
        """Get all active guest users in the tenant.
        
        Retrieves all active (accountEnabled=true) guest users from the tenant via MS Graph API,
        handling pagination automatically to ensure all guest users are returned.
        
        Parameters:
            use_cache (bool): If True, return cached guest users if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of active guest user objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-guests.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        url = f"https://{self.msgraph_domain}/v1.0/users?$filter=accountEnabled eq true and userType eq 'Guest'"
        url += "&$select=id,displayName,userPrincipalName,userType,identities"  # Select only relevant fields for guests
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        guest_users = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                guest_users.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch guest users: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched guest users
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(guest_users, f, indent=2)
        
        return guest_users

    def get_internal_guests(self, use_cache: bool = True) -> List[Dict]:
        """Get all internal guest users (local guests) in the tenant.
        
        Internal guests are guest accounts that belong to your own tenant (e.g., manually created
        guest accounts or ones created by apps). These are users whose userType is Guest and who
        are homed in your tenant (no external tenant indicator).
        
        Parameters:
            use_cache (bool): If True, return cached users if available. Default is True.

        Returns:
            List[Dict]: List of internal guest user objects
        """
        cache_file = self.cache_dir / "tenant" / "internal-guests.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Get all guest users first
        all_guests = self.get_all_active_guests(use_cache=use_cache)
        
        # Filter to internal guests
        internal_guests = []

        for guest in all_guests:
            if '#EXT#' not in guest.get('userPrincipalName', ''):
                internal_guests.append(guest)

        # Cache the results
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(internal_guests, f, indent=2)
        
        return internal_guests

    def get_b2b_collaboration_guests(self, use_cache: bool = True) -> List[Dict]:
        """Get all B2B collaboration guest users in the tenant.
        
        B2B collaboration guests are classic Azure AD / Entra B2B invited users that show up
        in your directory with userType = Guest and authenticate in their home tenant.
        
        Parameters:
            use_cache (bool): If True, return cached users if available. Default is True.

        Returns:
            List[Dict]: List of B2B collaboration guest user objects
        """
        cache_file = self.cache_dir / "tenant" / "b2b-collaboration-guests.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Get all guest users
        all_guests = self.get_all_active_guests(use_cache=use_cache)
        
        # Fitler to B2B guests
        b2b_guests = []

        for guest in all_guests:
            if '#EXT#' in guest.get('userPrincipalName', ''):
                b2b_guests.append(guest)

        # Cache the results
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(b2b_guests, f, indent=2)
        
        return b2b_guests

    def get_b2b_collaboration_members(self, use_cache: bool = True) -> List[Dict]:
        """Get all B2B collaboration member users in the tenant.
        
        B2B collaboration members are external users who participate in B2B collaboration but
        appear in your directory as userType = Member (common with Cross-tenant synchronization
        or specific provisioning flows).
        
        Parameters:
            use_cache (bool): If True, return cached users if available. Default is True.

        Returns:
            List[Dict]: List of B2B collaboration member user objects
        """
        cache_file = self.cache_dir / "tenant" / "b2b-collaboration-members.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        all_members = self.get_all_active_members(use_cache=use_cache)
        
        # Filter to B2B members
        b2b_members = []
        
        tenant_domain = self._get_tenant_domain()
        for member in all_members:
            # Check if member has any identities with an issuer different from our tenant domain
            identities = member.get('identities', [])
            is_external_b2b = any(
                id.get('issuer') and id.get('issuer') != tenant_domain
                for id in identities if isinstance(id, dict)
            )
            if is_external_b2b:
                b2b_members.append(member)

        # Cache the results
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(b2b_members, f, indent=2)
        
        return b2b_members

    def _get_tenant_domain(self) -> str:
        """Get the tenant's primary domain from the token or organization info.
        
        Returns:
            str: The tenant's primary domain
        """
        # Try to get from cached org info or make a quick API call
        try:
            url = f"https://{self.msgraph_domain}/v1.0/organization"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                orgs = data.get('value', [])
                if orgs:
                    domains = orgs[0].get('verifiedDomains', [])
                    for domain in domains:
                        if domain.get('isDefault'):
                            return domain.get('name', '')
        except:
            pass
        return ''

    def get_all_active_cloud_applications(self, use_cache: bool = True) -> List[Dict]:
        """Get all active cloud applications in the tenant.
        
        Retrieves all active (accountEnabled=true) cloud applications from the tenant via MS Graph API,
        handling pagination automatically to ensure all applications are returned.
        
        Parameters:
            use_cache (bool): If True, return cached applications if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of active cloud application objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-cloud-apps.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        url = f"https://{self.msgraph_domain}/beta/servicePrincipals?$filter=accountEnabled eq true and servicePrincipalType eq 'Application'"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "consistencyLevel": "eventual"
        }
        
        cloud_apps = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                cloud_apps.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch cloud apps: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched cloud apps
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(cloud_apps, f, indent=2)
            
        return cloud_apps

    def get_all_active_agent_identities(self, use_cache: bool = True) -> List[Dict]:
        """Get all active agent identities in the tenant.
        
        Retrieves all active (accountEnabled=true) agent identities from the tenant via MS Graph API,
        handling pagination automatically to ensure all users are returned.
        
        Parameters:
            use_cache (bool): If True, return cached agent identities if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of active agent identity objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-agent-identities.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        url = f"https://{self.msgraph_domain}/beta/serviceprincipals/graph.agentIdentity?$filter=accountEnabled eq true"

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        agent_identities = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                agent_identities.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch agent identities: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched agent identities
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(agent_identities, f, indent=2)
            
        return agent_identities

    def get_all_active_agent_blueprints(self, use_cache: bool = True) -> List[Dict]:
        """Get all active agent blueprints in the tenant.
        
        Retrieves all active (accountEnabled=true) agent blueprints from the tenant via MS Graph API,
        handling pagination automatically to ensure all blueprints are returned.
        
        Parameters:
            use_cache (bool): If True, return cached blueprints if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of agent blueprint objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "agent-blueprints.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        # Fetch agent blueprints using the suggested endpoint
        url = f"https://{self.msgraph_domain}/beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$filter=accountEnabled eq true"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        blueprints = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                blueprints.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch agent blueprints: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched blueprints
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(blueprints, f, indent=2)
            
        return blueprints

    def get_all_active_agent_resources(self, use_cache: bool = True) -> List[Dict]:
        """Get all agent resources (agent identities + agent blueprints) in the tenant.
        
        Combines agent identities and agent blueprints to provide the complete set
        of agent resources. This is useful for accurately identifying policies that
        target agent resources by their app IDs.
        
        Parameters:
            use_cache (bool): If True, return cached resources if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: Combined list of agent identity and blueprint objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-agent-resources.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Fetch both agent identities and blueprints
        agent_identities = self.get_all_active_agent_identities(use_cache=use_cache)
        agent_blueprints = self.get_all_active_agent_blueprints(use_cache=use_cache)
        
        # Combine into single list
        agent_resources = agent_identities + agent_blueprints
        
        # Cache the combined results
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(agent_resources, f, indent=2)
            
        return agent_resources

    def get_all_active_workload_identities(self, use_cache: bool = True) -> List[Dict]:
        """Get all active workload identities in the tenant.
        
        Retrieves all active (accountEnabled=true) workload identities from the tenant via MS Graph API,
        handling pagination automatically to ensure all users are returned.
        
        Parameters:
            use_cache (bool): If True, return cached agent identities if available. If False,
                            fetch fresh data from the API. Default is True.

        Returns:
            List[Dict]: List of active workload identity objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "active-workload-identities.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)

        # Get tenant ID
        tenant_id = None
        url = f"https://{self.msgraph_domain}/v1.0/organization"

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=30),
                skip_on_404=False
            )
            data = response.json()
            tenant_id = data.get('value')[0].get('id')
        except Exception as e:
            print(f"Failed to fetch tenant ID: {e}")
            print ("Could not retrieve workload identities without Tenant ID")
            return []

        # Workload Identities are single-tenant SPs registered in my tenant that are not Managed Identities
        url = f"https://{self.msgraph_domain}/v1.0/servicePrincipals?$count=true&$filter=accountEnabled eq true and servicePrincipalType eq 'Application' and appOwnerOrganizationId eq {tenant_id}"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual"
        }
        workload_identities = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=30),
                    skip_on_404=False
                )
                data = response.json()
                
                workload_identities.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch workload identities: {e}")
                break  # Exit pagination loop on error
            
        # Cache the fetched workload identities
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(workload_identities, f, indent=2)
            
        return workload_identities

    def get_named_locations(self, use_cache: bool = True) -> List[Dict]:
        """Fetch named locations from Microsoft Graph API.
        
        Retrieves all named locations configured in the tenant. Named locations
        can represent IP ranges, countries, or trusted network locations used
        in conditional access policies. Results are cached for performance.
        
        Parameters:
            use_cache (bool): If True, return cached locations if available. If False,
                            fetch fresh data from the API. Default is True.
        
        Returns:
            List[Dict]: List of named location objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "tenant" / "named-locations.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
                
        url = f"https://{self.msgraph_domain}/v1.0/identity/conditionalAccess/namedLocations"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        response = self._retry_on_failure(
            lambda: self.session.get(url, headers=headers, timeout=10)
        )
        
        data = response.json()
        locations = data.get('value', [])
        
        # Save locations to cache
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(locations, f, indent=2)
            
        return locations

    def get_authentication_contexts(self, use_cache: bool = True) -> List[Dict]:
        """Fetch authentication context class references from Microsoft Graph API.
        
        Retrieves all authentication context class references configured in the tenant.
        These are used in conditional access policies to require specific authentication
        strength for sensitive resources. Results are cached for performance.
        
        Parameters:
            use_cache (bool): If True, return cached contexts if available. If False,
                            fetch fresh data from the API. Default is True.
        
        Returns:
            List[Dict]: List of authentication context objects
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        cache_file = self.cache_dir / "policies" / "auth-contexts.json"
        
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
                
        url = f"https://{self.msgraph_domain}/v1.0/identity/conditionalAccess/authenticationContextClassReferences"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=10)
            )
            
            data = response.json()
            contexts = data.get('value', [])
            
            # Merge with existing cache (preserve any manually cached contexts)
            if cache_file.exists():
                try:
                    with open(cache_file, 'r') as f:
                        existing_contexts = json.load(f)
                    
                    # Build set of existing context IDs
                    existing_ids = {ctx.get('id') for ctx in existing_contexts if ctx.get('id')}
                    
                    # Add new contexts that aren't already cached
                    for context in contexts:
                        if context.get('id') not in existing_ids:
                            existing_contexts.append(context)
                    
                    # Update with merged list
                    contexts = existing_contexts
                except Exception as e:
                    print(f"Warning: Could not merge auth_contexts cache: {e}")
            
            # Save merged contexts cache
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(contexts, f, indent=2)
                
            return contexts
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"Authentication contexts endpoint not found (404): {e}")
                return []
            raise
        except Exception as e:
            print(f"Failed to fetch authentication contexts: {e}")
            return []
    
    def get_policies_for_gap_analysis(self, 
                                            use_cache: bool = True, 
                                            debug: bool = False,
                                            assignment_type: str = None,
                                            target_resource: str = None) -> tuple:
        """Fetch conditional access policies suitable for gap analysis.
        
        Retrieves all enabled conditional access policies and applies filtering
        to exclude policies that cannot be evaluated in gap analysis (e.g., device filters,
        risk-based policies, policies without grant controls or target applications).
        
        This method calls get_all_policies() first and then applies filtering rules on-the-fly.
        No separate caching is performed - filtering is fast and applied from policies.json.
        
        Parameters:
            use_cache (bool): If True, use cached policies.json if available. If False,
                            fetch fresh data from the API. Default is True.
            debug (bool): If True, print individual filtered policies. If False, collect statistics only.
            assignment_type (str): Filter by assignment type - 'users-groups-roles', 'agent-identities', 'workload-identities'
            target_resource (str): Filter by target resource - 'cloud-apps', 'user-actions', 'agent-resources'
        
        Returns:
            tuple: (filtered_policies, statistics_dict)
                - filtered_policies: List of enabled CA policy objects that meet evaluation criteria
                - statistics_dict: Dict with counts per filter reason
        
        Raises:
            ValueError: If token is invalid, expired, or lacks required permissions
        """
        # Get all policies from cache
        all_policies = self.get_all_policies(use_cache=use_cache)
        
        # Only include enabled policies
        policies = [p for p in all_policies if p.get('state') == 'enabled']
        
        # Initialize filter statistics
        filter_stats = {
            'total_policies': len(all_policies),
            'disabled_policies': len(all_policies) - len(policies),
            'no_grant_control': 0,
            'device_filter': 0,
            'auth_contexts': 0,
            'app_filter': 0,
            'no_target_apps': 0,
            'user_risk': 0,
            'signin_risk': 0,
            'sp_risk': 0,
            'insider_risk': 0,
            'time_based': 0,
            'weak_compliant_device': 0,
            'weak_app_protection': 0,
            'weak_domain_joined': 0,
            'weak_approved_app': 0,
            'weak_compliant_app': 0,
            'weak_password_change': 0,
            'weak_risk_remediation': 0,
            'weak_terms_of_use': 0,
            'assignment_mismatch': 0,
            'target_resource_mismatch': 0,
            'passed': 0
        }
        
        # Track excluded policies with their reasons for portal display
        excluded_policies = []
        
        # Filter out policies that cannot be evaluated
        filtered_policies = []
        
        for policy in policies:
            policy_name = policy.get('displayName', 'Unknown Policy')
            conditions = policy.get('conditions') or {}
            grant_controls = policy.get('grantControls') or {}

            # Grant controls: built-in controls (MFA, block, device join, etc.)
            built_in_controls = grant_controls.get('builtInControls')

            # Grant controls: Authentication strength
            auth_strength = grant_controls.get('authenticationStrength')

            # Application conditions
            applications = conditions.get('applications') or {}
            include_applications = applications.get('includeApplications')
            
            # Authentication context conditions
            auth_contexts = applications.get('includeAuthenticationContextClassReferences')

            # Application filter conditions
            app_filter = applications.get('applicationFilter')
            app_filter_include_mode = False
            if app_filter:
                app_filter_include_mode = app_filter.get('mode') == 'include'

            # Device filter conditions
            devices = conditions.get('devices') or {}
            device_filter = devices.get('deviceFilter') 
            device_filter_include_mode = False
            if device_filter:
                device_filter_include_mode = device_filter.get('mode') == 'include'
            
            # Risk level conditions
            user_risk_levels = conditions.get('userRiskLevels')
            sign_in_risk_levels = conditions.get('signInRiskLevels')
            service_principal_risk_levels = conditions.get('servicePrincipalRiskLevels')
            insider_risk_levels = conditions.get('insiderRiskLevels')

            # Time conditions
            times = conditions.get('times')

            # Apply filtering rules:

            # Exclude policies without grant controls (typically used for session controls only)
            if not built_in_controls and not auth_strength:
                filter_stats['no_grant_control'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'No grant control',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (no grant control)")
                continue

            # Exclude policies relying on authentication context conditions (depends on app logic to apply)
            if auth_contexts:
                filter_stats['auth_contexts'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Auth contexts (dependent on app logic)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: authentication contexts)")
                continue

            # Exclude policies relying on a application filters - SHOULD IMPLEMENT SUPPORT FOR THIS!
            if app_filter_include_mode:
                filter_stats['app_filter'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Application filter (weak control)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (not implemented yet: application filter)")
                continue

            # Exclude policies relying on device filter include conditions (no protection in c2 scenarios)
            if device_filter_include_mode:
                filter_stats['device_filter'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Device filter (weak control)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak control: device filter)")
                continue
            
            # Exclude policies relying on user risk level conditions (no guarantee of real-time signals)
            if user_risk_levels:
                filter_stats['user_risk'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'User risk (weak condition)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: user risk levels)")
                continue
            
            # Exclude policies relying on sign-in risk level conditions (no guarantee of real-time signals)
            if sign_in_risk_levels:
                filter_stats['signin_risk'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Sign-in risk (weak condition)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: sign-in risk levels)")
                continue
            
            # Exclude policies relying on service principal risk level conditions (no guarantee of real-time signals)
            if service_principal_risk_levels:
                filter_stats['sp_risk'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Service Principal risk (weak condition)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: service principal risk levels)")
                continue

            # Exclude policies using insider risk level conditions (no guarantee of real-time signals)
            if insider_risk_levels:
                filter_stats['insider_risk'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Insider risk (weak condition)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: insider risk levels)")
                continue
            
            # Exclude policies relying on time conditions (only apply during certain times)
            if times:
                filter_stats['time_based'] += 1
                excluded_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy_name,
                    'reason': 'Time-based (weak condition)',
                    'state': policy.get('state')
                })
                if debug:
                    print(f"Filtering out: {policy_name} (weak condition: time-based)")
                continue
            
            # Filter by assignment type (users-groups-roles vs external-users vs agent-identities vs workload-identities)
            if assignment_type:
                users = conditions.get('users', {})
                client_apps = conditions.get('clientApplications', {})
                targets_agent_identities = False
                targets_workload_identities = False
                targets_users_groups_roles = False
                targets_external_users = False

                if users:
                    targets_users_groups_roles = (
                        users.get('includeUsers') or users.get('excludeUsers') or
                        users.get('includeGroups') or users.get('excludeGroups') or
                        users.get('includeRoles') or users.get('excludeRoles')
                    )
                    
                    # Check for external users targeting
                    targets_external_users = (
                        users.get('includeGuestsOrExternalUsers') or 
                        users.get('excludeGuestsOrExternalUsers') or
                        ('GuestsOrExternalUsers' in (users.get('includeUsers', []) + users.get('excludeUsers', [])))
                    )

                if client_apps:
                    targets_agent_identities = (
                        client_apps.get('includeAgentIdServicePrincipals') or
                        client_apps.get('excludeAgentIdServicePrincipals')
                    )
                    targets_workload_identities = (
                        client_apps.get('includeServicePrincipals') or
                        client_apps.get('excludeServicePrincipals')
                    )

                if assignment_type == 'users-groups-roles':
                    # Only include policies targeting users, groups, or roles
                    if not targets_users_groups_roles:
                        filter_stats['assignment_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Not assigned to users, groups, or roles',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (not assigned to users, groups, or roles)")
                        continue
                elif assignment_type == 'guests':
                    # Only include policies targeting external/guest users
                    if not targets_external_users:
                        filter_stats['assignment_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Not assigned to external/guest users',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (not assigned to external/guest users)")
                        continue
                elif assignment_type == 'agent-identities':
                    # Only include policies targeting agent identities
                    if not targets_agent_identities:
                        filter_stats['assignment_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Not assigned to agent identities',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (not assigned to agent identities)")
                        continue
                elif assignment_type == 'workload-identities':
                    # Only include policies targeting workload identities (service principals)
                    if not targets_workload_identities:
                        filter_stats['assignment_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Not assigned to workload identities',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (not assigned to workload identities)")
                        continue

            
            # Filter by target resource type
            if target_resource:
                include_apps = applications.get('includeApplications', [])
                include_user_actions = applications.get('includeUserActions', [])

                # For agent resources: check for AllAgentIdResources keyword OR individual agent resource app IDs
                targets_agent_resources = 'AllAgentIdResources' in include_apps

                # If not using AllAgentIdResources, check if any app IDs match agent resources
                if target_resource == 'agent-resources' and not targets_agent_resources and include_apps:
                    # Fetch agent resources (cached) and extract app IDs
                    agent_resources = self.get_all_active_agent_resources(use_cache=use_cache)
                    agent_resource_app_ids = {ar.get('appId') for ar in agent_resources if ar.get('appId')}
                    
                    # Check if any included apps are agent resources
                    targets_agent_resources = any(app_id in agent_resource_app_ids for app_id in include_apps)
                
                targets_cloud_apps = bool(include_apps and not targets_agent_resources)
                targets_user_actions = bool(include_user_actions)

                if target_resource == 'cloud-apps':
                    # Only include policies targeting cloud apps
                    if not targets_cloud_apps:
                        filter_stats['target_resource_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': f"Does not target the requested scan type (cloud apps)",
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (does not target the requested scan type (cloud apps))")
                        continue
                elif target_resource == 'user-actions':
                    # Only include policies targeting user actions
                    if not targets_user_actions:
                        filter_stats['target_resource_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Does not target the requested scan type (user actions)',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (does not target the requested scan type (user actions))")
                        continue
                elif target_resource == 'agent-resources':
                    # Only include policies that specifically target agent resources
                    if not targets_agent_resources:
                        filter_stats['target_resource_mismatch'] += 1
                        excluded_policies.append({
                            'id': policy.get('id'),
                            'displayName': policy_name,
                            'reason': 'Does not target the requested scan type (agent resources)',
                            'state': policy.get('state')
                        })
                        if debug:
                            print(f"Filtering out: {policy_name} (does not target the requested scan type (agent resources))")
                        continue
            
            # Exclude policies with weak controls (!= block or mfa or auth strength)
            has_strong_control = any(c in ['block', 'mfa'] for c in built_in_controls) or auth_strength
            
            if not has_strong_control:
                # Check if it has any weak controls and track individually
                weak_control_found = False
                weak_controls_list = []
                
                if 'compliantDevice' in built_in_controls:
                    filter_stats['weak_compliant_device'] += 1
                    weak_controls_list.append('compliantDevice')
                    weak_control_found = True
                if 'domainJoinedDevice' in built_in_controls:
                    filter_stats['weak_domain_joined'] += 1
                    weak_controls_list.append('domainJoinedDevice')
                    weak_control_found = True
                if 'approvedApplication' in built_in_controls:
                    filter_stats['weak_approved_app'] += 1
                    weak_controls_list.append('approvedApplication')
                    weak_control_found = True
                if 'compliantApplication' in built_in_controls:
                    filter_stats['weak_compliant_app'] += 1
                    weak_controls_list.append('compliantApplication')
                    weak_control_found = True
                if 'passwordChange' in built_in_controls:
                    filter_stats['weak_password_change'] += 1
                    weak_controls_list.append('passwordChange')
                    weak_control_found = True
                if 'requireRiskRemediation' in built_in_controls:
                    filter_stats['weak_risk_remediation'] += 1
                    weak_controls_list.append('requireRiskRemediation')
                    weak_control_found = True
                if 'termsOfUse' in built_in_controls:
                    filter_stats['weak_terms_of_use'] += 1
                    weak_controls_list.append('termsOfUse')
                    weak_control_found = True
                
                if weak_control_found:
                    excluded_policies.append({
                        'id': policy.get('id'),
                        'displayName': policy_name,
                        'reason': f"Weak control(s): {', '.join(weak_controls_list)}",
                        'state': policy.get('state')
                    })
                    if debug:
                        print(f"Filtering out: {policy_name} (weak control(s): {', '.join(weak_controls_list)})")
                    continue

            # Policy passed all checks - include it
            filter_stats['passed'] += 1
            filtered_policies.append(policy)
        
        policies = filtered_policies
        
        # Return both policies and statistics
        # Caller can choose to display stats or not
        return_stats = filter_stats
        return_stats['excluded_policies'] = excluded_policies
        
        
        return policies, return_stats

    def resolve_id(self, object_id: str, id_cache: Dict[str, str], location_map: Dict[str, str] = None) -> str:
        """Resolve a directory object ID to its display name.
        
        Attempts to resolve a directory object (user, group, role, location) to
        a human-readable display name. Checks cache first, then location map,
        then falls back to Graph API lookup.
        
        Parameters:
            object_id (str): The GUID of the directory object to resolve
            id_cache (Dict[str, str]): Cache dictionary mapping IDs to display names
            location_map (Dict[str, str], optional): Pre-built mapping of location IDs
                                                     to names. Default is None.
        
        Returns:
            str: Display name, userPrincipalName, appId, or original ID if
                resolution fails
        """
        if not object_id:
            return object_id
        
        # Special CA keywords should not be resolved - return as-is
        # Check case-insensitively by capitalizing first letter (All, None, etc.)
        if object_id in SPECIAL_CA_VALUES or (isinstance(object_id, str) and object_id.capitalize() in SPECIAL_CA_VALUES):
            return object_id
            
        # Check cache first
        if object_id in id_cache:
            return id_cache[object_id]
            
        # Check location map
        if location_map and object_id in location_map:
            name = location_map[object_id]
            id_cache[object_id] = name
            return name
            
        # Try to resolve via Graph API
        url = f"https://{self.msgraph_domain}/v1.0/directoryObjects/{object_id}"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=10)
            )
            obj = response.json()
            name = obj.get('displayName') or obj.get('userPrincipalName') or obj.get('appId') or object_id
            id_cache[object_id] = name
            return name
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Object doesn't exist
                id_cache[object_id] = object_id
                return object_id
            # All retries failed
            id_cache[object_id] = object_id
            return object_id
        except Exception:
            # All retries failed
            id_cache[object_id] = object_id
            return object_id
    
    def resolve_list(self, items: List, id_cache: Dict[str, str], location_map: Dict[str, str] = None) -> List[str]:
        """Resolve a list of IDs or ID-containing dictionaries to display names.
        
        Batch resolves a list of items that can be either string IDs or dictionaries
        containing an 'id' field. Each item is resolved using resolve_id().
        
        Parameters:
            items (List): List of string IDs or dictionaries with 'id' key
            id_cache (Dict[str, str]): Cache dictionary mapping IDs to display names
            location_map (Dict[str, str], optional): Pre-built mapping of location IDs
                                                     to names. Default is None.
        
        Returns:
            List[str]: List of resolved display names in the same order as input
        """
        resolved = []
        for item in items or []:
            if isinstance(item, dict) and 'id' in item:
                resolved.append(self.resolve_id(item['id'], id_cache, location_map))
            elif isinstance(item, str):
                resolved.append(self.resolve_id(item, id_cache, location_map))
            else:
                resolved.append(str(item))
        return resolved
        
    def resolve_object(self, object_id: str) -> Optional[Dict]:
        """Resolve a single directory object by its ID.
        
        Fetches the full object details from the Graph API directoryObjects endpoint.
        Returns the complete object representation including type information.
        
        Parameters:
            object_id (str): The GUID of the directory object to resolve
        
        Returns:
            Optional[Dict]: Full directory object data, or None if resolution fails
        """ 
        url = f"https://{self.msgraph_domain}/v1.0/directoryObjects/{object_id}"

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=10)
            )
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Object deleted
                return None
            print(f"Failed to resolve object {object_id}: {e}")
            return None
        except Exception as e:
            print(f"Failed to resolve object {object_id}: {e}")
            return None
            
    def resolve_objects(self, object_ids: List[str]) -> Tuple[List[Dict], Set[str]]:
        """Resolve multiple directory objects in batch.
        
        Fetches full object details for a list of directory object IDs. Implements
        rate limiting (sleeps every 30 requests) to avoid throttling.
        
        Parameters:
            object_ids (List[str]): List of directory object GUIDs to resolve
        
        Returns:
            tuple[List[Dict], Set[str]]: Tuple containing:
                - List of successfully resolved directory objects
                - Set of object IDs that couldn't be resolved (deleted objects)
        """
        results = []
        deleted_ids = set()
        count = 0
        
        for oid in object_ids:
            count += 1
            if count % 30 == 0:
                time.sleep(1)  # Rate limiting
                
            obj = self.resolve_object(oid)
            if obj:
                results.append(obj)
            else:
                deleted_ids.add(oid)
                
        return results, deleted_ids
        
    def resolve_service_principal(self, app_id: str) -> Optional[Dict]:
        """Resolve a service principal by its application ID.
        
        Searches for a service principal using its appId (not object ID). Returns
        the service principal object with display name and IDs.
        
        Parameters:
            app_id (str): The application ID (appId, not object ID) to search for
        
        Returns:
            Optional[Dict]: Service principal object with appId, displayName, and id,
                          or None if not found or resolution fails
        """
        url = f"https://{self.msgraph_domain}/v1.0/serviceprincipals?$search=\"appId:{app_id}\"&$select=appId,displayName,id"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual"
        }
        
        try:
            response = self._retry_on_failure(
                lambda: self.session.get(url, headers=headers, timeout=10)
            )
            data = response.json()
            values = data.get('value', [])
            return values[0] if values else None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # App doesn't exist
                return None
            print(f"Failed to resolve app {app_id}: {e}")
            return None
        except Exception as e:
            print(f"Failed to resolve app {app_id}: {e}")
            return None
    
    def resolve_service_principals_by_ids(self, sp_ids: List[str]) -> List[Dict]:
        """Resolve service principals by their object IDs.
        
        Fetches service principal details for a list of object IDs. Used for resolving
        service principals referenced in client application conditions.
        
        Parameters:
            sp_ids (List[str]): List of service principal object IDs
        
        Returns:
            List[Dict]: List of service principal objects with id, displayName, and appId
        """
        results = []
        for sp_id in sp_ids:
            if not sp_id:
                continue
            url = f"https://{self.msgraph_domain}/v1.0/serviceprincipals/{sp_id}"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10)
                )
                results.append(response.json())
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    pass
                    #print(f"Service principal {sp_id} not found (404)")
                else:
                    print(f"Failed to resolve service principal {sp_id}: {e}")
            except Exception as e:
                print(f"Failed to resolve service principal {sp_id}: {e}")
            
            # Rate limiting
            if len(results) % 30 == 0:
                time.sleep(1)
        
        return results

    def resolve_agent_resources_by_ids(self, sp_ids: List[str]) -> List[Dict]:
        """Resolve Agent Resources by their object IDs.
        
        Fetches agent resource details for a list of service principal object IDs. Used for resolving
        agent resources referenced in client application conditions.
        
        Parameters:
            sp_ids (List[str]): List of service principal object IDs
        
        Returns:
            List[Dict]: List of agent resource objects with id, displayName, and appId
        """
        results = []
        all_agent_resources = self.get_all_active_agent_resources(use_cache=True)
        all_agent_resources_ids = [res['id'] for res in all_agent_resources]

        for sp_id in sp_ids:
            if not sp_id:
                continue
            # Check if the Service Principal is an Agent Resource
            if not sp_id in all_agent_resources_ids:
                continue

            url = f"https://{self.msgraph_domain}/v1.0/serviceprincipals/{sp_id}"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10)
                )
                results.append(response.json())
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    pass
                else:
                    print(f"Failed to resolve agent resource {sp_id}: {e}")
            except Exception as e:
                print(f"Failed to resolve agent resource {sp_id}: {e}")
            
            # Rate limiting
            if len(results) % 30 == 0:
                time.sleep(1)
        
        return results

    def get_group_members(self, group_id: str) -> List[Dict]:
        """Get all members of a group.
        
        Retrieves all members of a specified group, handling pagination automatically
        to ensure all members are returned even for large groups.
        
        Parameters:
            group_id (str): The object ID of the group
        
        Returns:
            List[Dict]: List of member objects (users, groups, service principals, etc.)
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        url = f"https://{self.msgraph_domain}/v1.0/groups/{group_id}/members?$top=999"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        members = []
        skip_on_404 = True
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10),
                    skip_on_404=skip_on_404 
                )
                data = response.json()
                
                members.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                if not (skip_on_404 and e.response and e.response.status_code == 404):
                    print(f"Failed to fetch group members: {e}")
                break  # Exit pagination loop on error
            
        return members
    
    def get_role_members(self, role_template_id: str) -> List[Dict]:
        """Get all members assigned to a directory role.
        
        Retrieves all members (typically users) assigned to a specified Entra ID directory role,
        handling pagination automatically to ensure all members are returned.
        
        Parameters:
            role_template_id (str): The object ID of the directory role template
        
        Returns:
            List[Dict]: List of member objects (users, service principals, etc.) assigned to the role
        
        Raises:
            requests.HTTPError: If the API request fails
        """
        url = f"https://{self.msgraph_domain}/v1.0/directoryRoles(roleTemplateId='{role_template_id}')/members"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        members = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10),
                    skip_on_404=True
                )
                data = response.json()
                
                members.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                # Role is not assigned anymore or has been deleted if custom
                #print(f"Failed to fetch role members for {role_template_id}: {e}")
                break  # Exit pagination loop on error
            
        return members
    
    def get_directory_role_members(self, role_id: str) -> List[Dict]:
        """Get all members assigned to a directory role by role ID (not template ID).
        
        Args:
            role_id: The object ID of the directory role instance
        
        Returns:
            List of member objects assigned to the role
        """
        url = f"https://{self.msgraph_domain}/v1.0/directoryRoles/{role_id}/members"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        members = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10),
                    skip_on_404=True
                )
                data = response.json()
                
                members.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to fetch directory role members for {role_id}: {e}")
                break
            
        return members
    
    def get_users_by_filter(self, filter_query: str) -> List[Dict]:
        """Query users using $filter parameter.
        
        Args:
            filter_query: OData filter expression (e.g., "userPrincipalName eq 'user@domain.com'")
        
        Returns:
            List of user objects matching the filter
        """
        url = f"https://{self.msgraph_domain}/v1.0/users?$filter={filter_query}"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        users = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10)
                )
                data = response.json()
                
                users.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to query users with filter '{filter_query}': {e}")
                break
            
        return users
    
    def get_groups_by_filter(self, filter_query: str) -> List[Dict]:
        """Query groups using $filter parameter.
        
        Args:
            filter_query: OData filter expression (e.g., "displayName eq 'Sales Team'")
        
        Returns:
            List of group objects matching the filter
        """
        url = f"https://{self.msgraph_domain}/v1.0/groups?$filter={filter_query}"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        groups = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10)
                )
                data = response.json()
                
                groups.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to query groups with filter '{filter_query}': {e}")
                break
            
        return groups
    
    def get_directory_roles_by_filter(self, filter_query: str) -> List[Dict]:
        """Query directory roles using $filter parameter.
        
        Args:
            filter_query: OData filter expression (e.g., "displayName eq 'Global Administrator'")
        
        Returns:
            List of directory role objects matching the filter
        """
        url = f"https://{self.msgraph_domain}/v1.0/directoryRoles?$filter={filter_query}"
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        roles = []
        
        while url:
            try:
                response = self._retry_on_failure(
                    lambda: self.session.get(url, headers=headers, timeout=10)
                )
                data = response.json()
                
                roles.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
            except Exception as e:
                print(f"Failed to query directory roles with filter '{filter_query}': {e}")
                break
            
        return roles
    
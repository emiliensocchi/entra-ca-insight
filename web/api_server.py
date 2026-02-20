"""
Flask API server for CA Insight - serves analysis data via REST endpoints
"""

# Standard library imports
import base64
import contextlib
import io
import importlib
import json
import multiprocessing
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Third-party imports
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import jwt
import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Local application imports
from caInsight.main import run_analysis
from caInsight.graph.api_client import GraphAPIClient
from caInsight.reports.generator import ReportGenerator
from caInsight.analyzer.mapper import UserMapper
from caInsight.filter_config import FilterConfig

app = Flask(__name__, static_folder='web')
CORS(app)

# Database path - use absolute path based on script location
DB_PATH = Path(__file__).parent.parent / 'caInsight.db'

# Track active scans for progress updates
active_scans = {}
scan_logs = {}  # Store scan output logs in memory
scan_processes = {}  # Track running processes by scan_id (instead of threads)


def init_db():
    """Initialize SQLite database for storing analysis results and scan management"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Metadata table for analysis runs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TIMESTAMP NOT NULL,
            tenant_id TEXT,
            total_permutations INTEGER,
            gaps INTEGER,
            excluded_policies_count INTEGER DEFAULT 0,
            json_file TEXT,
            version TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_identities INTEGER,
            mfa_coverage_pct REAL,
            auth_strength_coverage_pct REAL,
            block_coverage_pct REAL,
            included_users_count INTEGER,
            excluded_users_count INTEGER,
            analysis_duration_seconds REAL,
            total_identities_in_tenant INTEGER
        )
    ''')

    # Table for gap analysis results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS permutations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_run_id INTEGER NOT NULL,
            user_id TEXT,
            user_display_name TEXT,
            user_type TEXT,
            user_count INTEGER,
            resource_app_id TEXT,
            resource_app_name TEXT,
            client_app_type TEXT,
            platform TEXT,
            location_id TEXT,
            location_name TEXT,
            lineage TEXT,
            terminated INTEGER NOT NULL,
            resource_app_count INTEGER,
            location_count INTEGER,
            client_app_type_count INTEGER,
            is_universal_gap INTEGER DEFAULT 0,
            FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # Table for excluded policies
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS excluded_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_run_id INTEGER NOT NULL,
            policy_id TEXT NOT NULL,
            display_name TEXT,
            state TEXT,
            reason TEXT,
            created_datetime TEXT,
            modified_datetime TEXT,
            conditions TEXT,
            grant_controls TEXT,
            session_controls TEXT,
            FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # Table for scan management
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL,
            assignments TEXT NOT NULL,
            target_resources TEXT NOT NULL,
            conditions TEXT,
            threads INTEGER,
            result_path TEXT,
            analysis_run_id INTEGER,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            error TEXT,
            permutation_count INTEGER,
            progress_percent INTEGER DEFAULT 0,
            include_object_ids TEXT,
            skip_object_ids TEXT,
            logs TEXT,
            FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # Create indexes for faster querying
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_name ON permutations(user_display_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_app_name ON permutations(resource_app_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_terminated ON permutations(terminated)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_run ON permutations(analysis_run_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_excluded_run ON excluded_policies(analysis_run_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_status ON scans(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_started ON scans(started_at)')
    
    # Database migrations - add columns if they don't exist
    # Check if reason column exists in excluded_policies
    cursor.execute("PRAGMA table_info(excluded_policies)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'reason' not in columns:
        cursor.execute('ALTER TABLE excluded_policies ADD COLUMN reason TEXT')
    
    # Check if count columns exist in permutations table (for critical gap scenarios)
    cursor.execute("PRAGMA table_info(permutations)")
    perm_columns = [row[1] for row in cursor.fetchall()]
    if 'resource_app_count' not in perm_columns:
        cursor.execute('ALTER TABLE permutations ADD COLUMN resource_app_count INTEGER')
    if 'location_count' not in perm_columns:
        cursor.execute('ALTER TABLE permutations ADD COLUMN location_count INTEGER')
    if 'client_app_type_count' not in perm_columns:
        cursor.execute('ALTER TABLE permutations ADD COLUMN client_app_type_count INTEGER')
    if 'is_universal_gap' not in perm_columns:
        cursor.execute('ALTER TABLE permutations ADD COLUMN is_universal_gap INTEGER DEFAULT 0')
    
    # Check if tenant_id column exists in scans table
    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = [row[1] for row in cursor.fetchall()]
    if 'tenant_id' not in scan_columns:
        cursor.execute('ALTER TABLE scans ADD COLUMN tenant_id TEXT')
    if 'tenant_domain' not in scan_columns:
        cursor.execute('ALTER TABLE scans ADD COLUMN tenant_domain TEXT')
    
    # Check if universal coverage columns exist in analysis_runs table
    cursor.execute("PRAGMA table_info(analysis_runs)")
    runs_columns = [row[1] for row in cursor.fetchall()]
    migrations_performed = []
    
    if 'total_identities' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN total_identities INTEGER')
        migrations_performed.append('total_identities')
    if 'mfa_coverage_pct' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN mfa_coverage_pct REAL')
        migrations_performed.append('mfa_coverage_pct')
    if 'auth_strength_coverage_pct' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN auth_strength_coverage_pct REAL')
        migrations_performed.append('auth_strength_coverage_pct')
    if 'block_coverage_pct' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN block_coverage_pct REAL')
        migrations_performed.append('block_coverage_pct')
    if 'identities_with_gaps' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN identities_with_gaps INTEGER')
        migrations_performed.append('identities_with_gaps')
    if 'included_users_count' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN included_users_count INTEGER')
        migrations_performed.append('included_users_count')
    if 'excluded_users_count' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN excluded_users_count INTEGER')
        migrations_performed.append('excluded_users_count')
    if 'analysis_duration_seconds' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN analysis_duration_seconds REAL')
        migrations_performed.append('analysis_duration_seconds')
    if 'total_identities_in_tenant' not in runs_columns:
        cursor.execute('ALTER TABLE analysis_runs ADD COLUMN total_identities_in_tenant INTEGER')
        migrations_performed.append('total_identities_in_tenant')
    
    if migrations_performed:
        print(f"Database migrations applied: {', '.join(migrations_performed)}")
    
    conn.commit()
    conn.close()


def import_json_to_db(json_file: str) -> int:
    """Import a JSON analysis report into the database.
    
    Parameters:
        json_file: Path to JSON report file
        
    Returns:
        int: ID of the created analysis run
    """
    # Ensure database is initialized before import
    if not DB_PATH.exists():
        init_db()
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Insert analysis run
    metadata = data['metadata']
    universal_coverage = metadata.get('universalCoverage', {})
    filter_statistics = metadata.get('filterStatistics', {})
    
    identities_with_gaps = universal_coverage.get('identities_with_gaps')
    
    cursor.execute('''
        INSERT INTO analysis_runs (generated_at, tenant_id, total_permutations, gaps, excluded_policies_count, json_file, version,
                                   total_identities, mfa_coverage_pct, auth_strength_coverage_pct, block_coverage_pct, identities_with_gaps,
                                   included_users_count, excluded_users_count, analysis_duration_seconds, total_identities_in_tenant)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        metadata['generatedAt'],
        metadata.get('tenantId'),
        metadata['totalPermutations'],
        metadata['gaps'],
        metadata.get('excludedPoliciesCount', 0),
        json_file,
        metadata.get('version', '1.0'),
        universal_coverage.get('total_identities'),
        universal_coverage.get('mfa_coverage_pct'),
        universal_coverage.get('auth_strength_coverage_pct'),
        universal_coverage.get('block_coverage_pct'),
        identities_with_gaps,
        filter_statistics.get('includedUsersCount'),
        filter_statistics.get('excludedUsersCount'),
        metadata.get('analysisDurationSeconds'),
        filter_statistics.get('totalIdentitiesInTenant')
    ))
    
    run_id = cursor.lastrowid
    
    # Insert permutations
    for result in data['results']:
        perm = result['permutation']
        is_terminated = result.get('terminated', False)
        
        # Dynamically detect identity type (users, agents, or workload_identities)
        identity_id = None
        identity_display_name = None
        identity_type = None
        identity_user_count = None
        
        # Get identity information from gap_source (current JSON format)
        gap_source = result.get('gap_source')
        if gap_source:
            identity_id = gap_source.get('id')
            identity_display_name = gap_source.get('displayName')
            identity_type = gap_source.get('type')
        else:
            # Fall back to checking permutation keys directly (critical gap scenario)
            for identity_key in ['users', 'guests', 'agents', 'workloadIdentities']:
                if identity_key in perm:
                    identity_obj = perm[identity_key]
                    if isinstance(identity_obj, dict):
                        identity_id = identity_obj.get('id')
                        identity_display_name = identity_obj.get('displayName')
                        identity_type = identity_obj.get('type')
                        identity_user_count = identity_obj.get('count')
                        
                        # Map identity_key to proper type if not already set
                        if not identity_type or identity_type == 'all':
                            if identity_key == 'users':
                                identity_type = 'user'
                            elif identity_key == 'guests':
                                identity_type = 'guest'
                            elif identity_key == 'agents':
                                identity_type = 'agent_identity'
                            elif identity_key == 'workloadIdentities':
                                identity_type = 'workload_identity'
                    elif isinstance(identity_obj, str):
                        identity_id = identity_obj
                        identity_display_name = identity_obj
                        identity_type = 'unknown'
                    break
        
        # Dynamically detect resource type (resourceApps, userActions, or agentResources)
        resource_id = None
        resource_display_name = None
        
        # Check for flat format first (application, userAction fields)
        if 'application' in perm:
            resource_id = perm['application']
            resource_display_name = perm['application']
        elif 'userAction' in perm:
            resource_id = perm['userAction']
            resource_display_name = perm['userAction']
        else:
            # Fall back to nested format
            for resource_key in ['resourceApps', 'userActions', 'agentResources']:
                if resource_key in perm:
                    resource_obj = perm[resource_key]
                    if isinstance(resource_obj, dict):
                        resource_id = resource_obj.get('id')
                        resource_display_name = resource_obj.get('displayName')
                    elif isinstance(resource_obj, str):
                        # Handle simple string values like "all"
                        resource_id = resource_obj
                        resource_display_name = resource_obj
                    break
        
        # Extract count values from permutation dimensions (for critical gap scenarios)
        resource_app_count = None
        location_count = None
        client_app_type_count = None
        
        for resource_key in ['resourceApps', 'userActions', 'agentResources']:
            if resource_key in perm and isinstance(perm[resource_key], dict):
                count_value = perm[resource_key].get('count')
                # Keep numeric counts, convert 'all' string to None
                if count_value is not None and count_value != 'all':
                    resource_app_count = count_value
                break
        
        locations_obj = perm.get('locations')
        if isinstance(locations_obj, dict):
            count_value = locations_obj.get('count')
            # Keep numeric counts, convert 'all' string to None
            if count_value is not None and count_value != 'all':
                location_count = count_value
        
        client_app_types_obj = perm.get('clientAppTypes')
        if isinstance(client_app_types_obj, dict):
            count_value = client_app_types_obj.get('count')
            # Keep numeric counts, convert 'all' string to None
            if count_value is not None and count_value != 'all':
                client_app_type_count = count_value
        
        # Check if this is a universal gap
        is_universal_gap = result.get('is_universal_gap', False)
        
        cursor.execute('''
            INSERT INTO permutations (
                analysis_run_id, user_id, user_display_name, user_type, user_count,
                resource_app_id, resource_app_name, client_app_type, platform,
                location_id, location_name, lineage, terminated,
                resource_app_count, location_count, client_app_type_count, is_universal_gap
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id,
            identity_id,
            identity_display_name,
            identity_type,
            identity_user_count if identity_user_count is not None else None,
            resource_id,
            resource_display_name,
            # Handle both flat format (clientAppType) and nested format (clientAppTypes.id)
            perm.get('clientAppType') if 'clientAppType' in perm else (perm.get('clientAppTypes', {}).get('id') if isinstance(perm.get('clientAppTypes'), dict) else perm.get('clientAppTypes')),
            # Handle both flat format (platform) and nested format (platforms)
            perm.get('platform') if 'platform' in perm else perm.get('platforms'),
            # Handle both flat format (location) and nested format (locations.id)
            perm.get('location') if 'location' in perm else (perm.get('locations', {}).get('id') if isinstance(perm.get('locations'), dict) else perm.get('locations')),
            # Location name (for flat format, use the location ID as name for now)
            perm.get('location') if 'location' in perm else (perm.get('locations', {}).get('displayName') if isinstance(perm.get('locations'), dict) else perm.get('locations')),
            result.get('lineage'),
            1 if is_terminated else 0,
            resource_app_count,
            location_count,
            client_app_type_count,
            1 if is_universal_gap else 0
        ))
    
    # Insert excluded policies
    excluded_policies = data.get('excludedPolicies', [])
    for policy in excluded_policies:
        cursor.execute('''
            INSERT INTO excluded_policies (
                analysis_run_id, policy_id, display_name, state, reason,
                created_datetime, modified_datetime, conditions,
                grant_controls, session_controls
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id,
            policy.get('id'),
            policy.get('displayName'),
            policy.get('state'),
            policy.get('reason'),
            policy.get('createdDateTime'),
            policy.get('modifiedDateTime'),
            json.dumps(policy.get('conditions')) if policy.get('conditions') else None,
            json.dumps(policy.get('grantControls')) if policy.get('grantControls') else None,
            json.dumps(policy.get('sessionControls')) if policy.get('sessionControls') else None
        ))
    
    # Detect target_resources and assignment types
    # Strategy: 1) Parse from filename, 2) Check results, 3) Default
    target_resources = 'cloud-apps'  # default
    assignments = 'users'  # default
    
    # Try to parse from filename (most reliable, works even with 0 results)
    # Expected format: YYYY-MM-DD_HH-MM-SS_cainsight_report_{source}_{assignments}_{target-resources}.json
    filename = Path(json_file).name
    filename_parts = filename.replace('.json', '').split('_')
    
    # Look for known assignment and target resource keywords in filename
    if len(filename_parts) >= 6:  # Has enough parts to contain config info
        for part in filename_parts:
            # Check for assignment types
            if part in ['users', 'guests', 'agent-identities', 'workload-identities']:
                assignments = part
            # Check for target resource types
            elif part in ['cloud-apps', 'user-actions', 'agent-resources']:
                target_resources = part
    
    # If filename parsing didn't work, try detecting from results data
    if data.get('results') and len(data['results']) > 0:
        first_perm = data['results'][0]['permutation']
        
        # Detect target_resources from permutation keys (override filename if found)
        if 'userActions' in first_perm:
            target_resources = 'user-actions'
        elif 'agentResources' in first_perm:
            target_resources = 'agent-resources'
        elif 'resourceApps' in first_perm:
            target_resources = 'cloud-apps'
        
        # Detect assignment type from permutation keys (override filename if found)
        if 'agents' in first_perm:
            assignments = 'agent-identities'
        elif 'workloadIdentities' in first_perm:
            assignments = 'workload-identities'
        elif 'guests' in first_perm:
            assignments = 'guests'
        elif 'users' in first_perm:
            assignments = 'users'
    
    # Read tenant domain from metadata (if available)
    tenant_id = metadata.get('tenantId')
    tenant_domain = metadata.get('primaryDomain')
    
    # Create a linked scan record to store target_resources metadata
    cursor.execute('''
        INSERT INTO scans (
            status, assignments, target_resources, started_at, completed_at, 
            analysis_run_id, result_path, permutation_count, progress_percent, tenant_id, tenant_domain
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        'completed',
        assignments,
        target_resources,
        metadata['generatedAt'],
        metadata['generatedAt'],
        run_id,
        json_file,
        metadata['totalPermutations'],
        100,
        tenant_id,
        tenant_domain
    ))
    
    conn.commit()
    conn.close()
    
    return run_id


# API Routes

@app.route('/')
def index():
    """Serve the main web portal"""
    # Generate portal.html from template if it doesn't exist
    portal_path = Path(__file__).parent.parent / 'portal.html'
    template_path = Path(__file__).parent.parent / 'templates' / 'portal-template.html'
    
    # Always serve fresh template (this ensures updates are reflected)
    if not portal_path.exists() or template_path.stat().st_mtime > portal_path.stat().st_mtime:
        # Copy template to portal.html
        shutil.copy(template_path, portal_path)
        print(f"Generated portal.html from template")
    
    return send_from_directory('..', 'portal.html')


@app.route('/api/runs', methods=['GET'])
def get_runs():
    """Get list of all analysis runs"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, generated_at, tenant_id, total_permutations, gaps, 
               excluded_policies_count, version, created_at,
               included_users_count, excluded_users_count, analysis_duration_seconds
        FROM analysis_runs
        ORDER BY created_at DESC
    ''')
    
    runs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(runs)


@app.route('/api/runs/<int:run_id>/summary', methods=['GET'])
def get_run_summary(run_id):
    """Get summary statistics for a specific run"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get run metadata
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    
    if not run:
        return jsonify({'error': 'Run not found'}), 404
    
    # Get target_resources, assignments and filter config from linked scan (if available)
    cursor.execute('SELECT target_resources, assignments, include_object_ids, skip_object_ids FROM scans WHERE analysis_run_id = ?', (run_id,))
    scan = cursor.fetchone()
    
    conn.close()
    
    run_dict = dict(run)
    # Add target_resources, assignments and filter config if scan was found
    if scan:
        run_dict['target_resources'] = scan['target_resources']
        run_dict['assignments'] = scan['assignments']
        run_dict['include_object_ids'] = scan['include_object_ids']
        run_dict['skip_object_ids'] = scan['skip_object_ids']
    
    return jsonify({
        'run': run_dict
    })


@app.route('/api/runs/<int:run_id>/excluded-policies', methods=['GET'])
def get_excluded_policies(run_id):
    """Get list of policies excluded from gap analysis for a specific run"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if run exists
    cursor.execute('SELECT id FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    
    if not run:
        conn.close()
        return jsonify({'error': 'Run not found'}), 404
    
    # Get excluded policies from database
    cursor.execute('''
        SELECT policy_id, display_name, state, reason, created_datetime, modified_datetime,
               conditions, grant_controls, session_controls
        FROM excluded_policies
        WHERE analysis_run_id = ?
    ''', (run_id,))
    
    policies = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries and parse JSON fields
    excluded_policies = []
    for policy in policies:
        policy_dict = {
            'id': policy['policy_id'],
            'displayName': policy['display_name'],
            'state': policy['state'],
            'reason': policy['reason'],
            'createdDateTime': policy['created_datetime'],
            'modifiedDateTime': policy['modified_datetime']
        }
        
        # Parse JSON fields
        if policy['conditions']:
            policy_dict['conditions'] = json.loads(policy['conditions'])
        if policy['grant_controls']:
            policy_dict['grantControls'] = json.loads(policy['grant_controls'])
        if policy['session_controls']:
            policy_dict['sessionControls'] = json.loads(policy['session_controls'])
        
        excluded_policies.append(policy_dict)
    
    return jsonify({
        'excludedPolicies': excluded_policies,
        'count': len(excluded_policies)
    })


@app.route('/api/runs/<int:run_id>/users', methods=['GET'])
def get_users_aggregated(run_id):
    """Get aggregated gap statistics by user for a specific run"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get aggregated stats per user (only gaps/unterminated)
    cursor.execute('''
        SELECT 
            user_id,
            user_display_name,
            user_type,
            user_count,
            COUNT(*) as gap_count,
            MAX(resource_app_count) as stored_app_count,
            MAX(location_count) as stored_location_count,
            MAX(client_app_type_count) as stored_client_type_count,
            COUNT(DISTINCT resource_app_id) as unique_apps,
            COUNT(DISTINCT platform) as unique_platforms,
            COUNT(DISTINCT location_id) as unique_locations,
            COUNT(DISTINCT client_app_type) as unique_client_types,
            MAX(is_universal_gap) as is_universal_gap
        FROM permutations
        WHERE analysis_run_id = ? AND terminated = 0
        GROUP BY user_id, user_display_name, user_type, user_count
        ORDER BY gap_count DESC, user_display_name
    ''', (run_id,))
    
    users = []
    for row in cursor.fetchall():
        # For universal gaps (user_id = 'all'), use stored counts if available
        # For regular gaps, use distinct counts (since stored_count is None)
        is_universal = row['user_id'] == 'all'
        
        # Use stored counts if available, otherwise use distinct counts
        # For universal gaps with empty permutations, distinct counts will be 0
        unique_apps = row['stored_app_count'] if row['stored_app_count'] is not None else row['unique_apps']
        unique_locations = row['stored_location_count'] if row['stored_location_count'] is not None else row['unique_locations']
        unique_client_types = row['stored_client_type_count'] if row['stored_client_type_count'] is not None else row['unique_client_types']
        
        users.append({
            'user_id': row['user_id'],
            'user_display_name': row['user_display_name'],
            'user_type': row['user_type'],
            'user_count': row['user_count'] if row['user_count'] is not None else None,
            'gap_count': row['gap_count'],
            'unique_apps': unique_apps,
            'unique_locations': unique_locations,
            'unique_client_types': unique_client_types,
            'is_universal_gap': bool(row['is_universal_gap']) if row['is_universal_gap'] is not None else False
        })
    
    conn.close()
    
    return jsonify({
        'total_users': len(users),
        'users': users
    })


@app.route('/api/runs/<int:run_id>/permutations', methods=['GET'])
def get_permutations(run_id):
    """Get permutations for a specific run with filtering and pagination"""
    # Parse query parameters
    user_filter = request.args.get('user', '')
    user_id = request.args.get('user_id', '')  # Exact user ID match
    app_filter = request.args.get('app', '')
    show_type = request.args.get('type', 'all')  # all, gaps, protected
    limit = int(request.args.get('limit', 20))  # Default to 20 for pagination
    offset = int(request.args.get('offset', 0))
    
    # Additional dimension filters for detail view
    client_app_type = request.args.get('client_app_type', '')
    location_name = request.args.get('location_name', '')
    platform = request.args.get('platform', '')
    resource_app_name = request.args.get('resource_app_name', '')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Build query with filters
    query = 'SELECT * FROM permutations WHERE analysis_run_id = ?'
    params = [run_id]
    
    if user_id:
        query += ' AND user_id = ?'
        params.append(user_id)
    elif user_filter:
        query += ' AND user_display_name LIKE ?'
        params.append(f'%{user_filter}%')
    
    if app_filter:
        query += ' AND resource_app_name LIKE ?'
        params.append(f'%{app_filter}%')
    
    if show_type == 'gaps':
        query += ' AND terminated = 0'
    elif show_type == 'protected':
        query += ' AND terminated = 1'
    
    # Apply dimension filters
    if client_app_type:
        query += ' AND client_app_type = ?'
        params.append(client_app_type)
    
    if location_name:
        query += ' AND location_name = ?'
        params.append(location_name)
    
    if platform:
        query += ' AND platform = ?'
        params.append(platform)
    
    if resource_app_name:
        query += ' AND resource_app_name = ?'
        params.append(resource_app_name)
    
    # Get total count
    count_query = f'SELECT COUNT(*) as total FROM ({query})'
    cursor.execute(count_query, params)
    total = cursor.fetchone()['total']
    
    # Get paginated results
    query += ' ORDER BY user_display_name LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    results = []
    
    for row in cursor.fetchall():
        result = dict(row)
        # Provide empty list for gaps, None for terminated
        result['policies'] = [] if result.get('terminated') == 0 else None
        
        # Convert SQLite integer booleans to Python booleans
        if 'is_universal_gap' in result:
            result['is_universal_gap'] = bool(result['is_universal_gap'])
        
        # Build display-friendly lineage with resolved names instead of IDs
        lineage_parts = []
        if result.get('user_display_name'):
            lineage_parts.append(f"User: {result['user_display_name']}")
        if result.get('client_app_type'):
            lineage_parts.append(f"Client: {result['client_app_type']}")
        if result.get('location_name'):
            lineage_parts.append(f"Location: {result['location_name']}")
        if result.get('platform'):
            lineage_parts.append(f"Platform: {result['platform']}")
        if result.get('resource_app_name'):
            lineage_parts.append(f"App: {result['resource_app_name']}")
        
        result['lineage_display'] = ' → '.join(lineage_parts) if lineage_parts else 'No lineage'
        
        results.append(result)
    
    conn.close()
    
    return jsonify({
        'total': total,
        'limit': limit,
        'offset': offset,
        'results': results
    })


@app.route('/api/runs/<int:run_id>/filter-values', methods=['GET'])
def get_filter_values(run_id):
    """Get all unique dimension values for filter dropdowns without pagination.
    
    This endpoint returns all unique values for each dimension (location, platform, etc.)
    for building filter dropdowns. Unlike get_permutations, this is not paginated to ensure
    all possible filter values are available even when there are thousands of gaps.
    """
    user_id = request.args.get('user_id', '')
    show_type = request.args.get('type', 'gaps')  # Default to gaps for detail view
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Build base query
    query = 'SELECT DISTINCT client_app_type, location_name, platform, resource_app_name FROM permutations WHERE analysis_run_id = ?'
    params = [run_id]
    
    if user_id:
        query += ' AND user_id = ?'
        params.append(user_id)
    
    if show_type == 'gaps':
        query += ' AND terminated = 0'
    elif show_type == 'protected':
        query += ' AND terminated = 1'
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Collect unique values for each dimension
    unique_values = {
        'client_app_types': set(),
        'locations': set(),
        'platforms': set(),
        'resource_apps': set()
    }
    
    for row in rows:
        if row['client_app_type']:
            unique_values['client_app_types'].add(row['client_app_type'])
        if row['location_name']:
            unique_values['locations'].add(row['location_name'])
        if row['platform']:
            unique_values['platforms'].add(row['platform'])
        if row['resource_app_name']:
            unique_values['resource_apps'].add(row['resource_app_name'])
    
    conn.close()
    
    # Convert sets to sorted lists
    return jsonify({
        'client_app_types': sorted(unique_values['client_app_types']),
        'locations': sorted(unique_values['locations']),
        'platforms': sorted(unique_values['platforms']),
        'resource_apps': sorted(unique_values['resource_apps'])
    })


@app.route('/api/upload', methods=['POST'])
def upload_analysis():
    """Upload and import a JSON analysis file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.json'):
        return jsonify({'error': 'File must be JSON'}), 400
    
    # Get optional token from form data for fetching tenant domain
    token = request.form.get('token')
    
    # Save temporarily for import
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    temp_filename = f"temp_upload_{timestamp}_{file.filename}"
    temp_path = Path(temp_filename)
    try:
        file.save(temp_path)
        print(f"File saved to {temp_path}, starting import...")
        run_id = import_json_to_db(str(temp_path))
        print(f"Import successful, run_id: {run_id}")
        
        # If token is provided, fetch and update tenant domain
        if token:
            try:
                tenant_domain = get_tenant_primary_domain(token)
                if tenant_domain:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE scans 
                        SET tenant_domain = ?
                        WHERE analysis_run_id = ?
                    ''', (tenant_domain, run_id))
                    conn.commit()
                    conn.close()
                    print(f"Updated scan with tenant domain: {tenant_domain}")
            except Exception as e:
                print(f"Warning: Could not fetch tenant domain: {e}")
                # Don't fail the upload if domain fetch fails
        
        # Delete the temporary file after successful import (data now in database)
        temp_path.unlink()
        print(f"Temporary file {temp_path} deleted")
        return jsonify({'success': True, 'run_id': run_id})
    except Exception as e:
        print(f"Import error: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        if temp_path.exists():
            temp_path.unlink()  # Clean up on error
        return jsonify({'success': False, 'error': f'{type(e).__name__}: {str(e)}'}), 500


def get_tenant_primary_domain(token: str) -> str:
    """Get the primary domain name for a tenant from Microsoft Graph.
    
    Parameters:
        token: Microsoft Graph access token
        
    Returns:
        Primary domain name or None if unavailable
    """
    try:
        headers = {'Authorization': f'Bearer {token}'}
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
                        domain_name = domain.get('name')
                        print(f"[get_tenant_primary_domain] Found primary domain: {domain_name}")
                        return domain_name
                print(f"[get_tenant_primary_domain] No primary/initial domain found in {len(verified_domains)} domains")
        else:
            print(f"[get_tenant_primary_domain] API request failed: {response.status_code}")
        return None
    except Exception as e:
        print(f"[get_tenant_primary_domain] Exception: {type(e).__name__}: {str(e)}")
        return None


@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Validate a Microsoft Graph access token."""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'valid': False, 'error': 'No token provided'}), 400
    
    try:
        client = GraphAPIClient(token)
        is_valid, error_msg = client.validate_token()
        
        if is_valid:
            return jsonify({'valid': True})
        else:
            return jsonify({'valid': False, 'error': error_msg}), 401
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500


@app.route('/api/extract-tenant-id', methods=['POST'])
def extract_tenant_id():
    """Extract tenant ID from JWT token without full validation."""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'tenant_id': None, 'error': 'No token provided'}), 400
    
    try:
        # Decode without verification to extract tenant ID
        decoded = jwt.decode(token, options={"verify_signature": False})
        tenant_id = decoded.get('tid')
        
        if tenant_id:
            return jsonify({'tenant_id': tenant_id})
        else:
            return jsonify({'tenant_id': None, 'error': 'No tenant ID found in token'}), 400
    except Exception as e:
        return jsonify({'tenant_id': None, 'error': f'Failed to decode token: {str(e)}'}), 400


@app.route('/api/policies', methods=['POST'])
def get_policies():
    """Fetch conditional access policies and return policy browser HTML."""
    data = request.get_json()
    token = data.get('token') if data else None
    
    if not token:
        return jsonify({'error': 'No token provided'}), 400
    
    try:
        client = GraphAPIClient(token)
        
        # Validate token first
        is_valid, error_msg = client.validate_token()
        if not is_valid:
            return jsonify({'error': f'Invalid token: {error_msg}'}), 401
        
        # Fetch fresh policies from tenant (will update cache for CLI use)
        policies = client.get_all_policies(use_cache=False)
        named_locations = client.get_named_locations(use_cache=False)
        
        # Initialize mapper to resolve IDs
        mapper = UserMapper(client)
        
        # Generate policy browser HTML using existing code
        # Note: Policy browser doesn't need assignment/target_resource since it doesn't generate files
        generator = ReportGenerator(token=token, api_client=client, source='web')
        policy_browser_html = generator.generate_policy_browser_html(policies, named_locations, mapper)
        
        return jsonify({
            'html': policy_browser_html,
            'count': len(policies)
        })
    except Exception as e:
        print(f"Error fetching policies: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats/overall', methods=['GET'])
def get_overall_stats():
    """Get overall statistics across all runs"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as total_runs FROM analysis_runs')
    total_runs = cursor.fetchone()['total_runs']
    
    cursor.execute('SELECT SUM(total_permutations) as total FROM analysis_runs')
    total_perms = cursor.fetchone()['total'] or 0
    
    cursor.execute('SELECT SUM(gaps) as total FROM analysis_runs')
    total_gaps = cursor.fetchone()['total'] or 0
    
    conn.close()
    
    return jsonify({
        'totalRuns': total_runs,
        'totalPermutations': total_perms,
        'totalGaps': total_gaps,
        'coverageRate': ((total_perms - total_gaps) / total_perms * 100) if total_perms > 0 else 0
    })


# ============================================================================
# SCAN MANAGEMENT ENDPOINTS
# ============================================================================

def run_scan_background(scan_id: int, token: str, config: dict):
    """Run scan in background process - wrapper for multiprocessing."""
    # Start the scan in a separate process with fresh Python environment
    # Use spawn method to ensure clean process without inherited state
    ctx = multiprocessing.get_context('spawn')
    process = ctx.Process(
        target=_run_scan_worker,
        args=(scan_id, token, config, DB_PATH),
        daemon=False  # Explicitly set daemon=False to ensure clean termination
    )
    process.start()
    scan_processes[scan_id] = process
    
    return process


def _run_scan_worker(scan_id: int, token: str, config: dict, db_path: Path):
    """Worker function that runs in a separate process."""
    # Clear module cache and force reimport to get latest code in worker process
    if 'caInsight.main' in sys.modules:
        del sys.modules['caInsight.main']
    if 'caInsight.analyzer.permutations' in sys.modules:
        del sys.modules['caInsight.analyzer.permutations']
    
    # Re-import to get fresh code in worker process
    from caInsight.main import run_analysis
    
    # Initialize log storage for this scan (in worker process)
    process_logs = []
    
    def progress_callback(percent, message: str):
        """Update scan progress in database. Accepts int or float."""
        try:
            # Convert to int if needed (e.g., 85.5 -> 85)
            percent_int = int(percent) if percent is not None else 0
            
            # Store log message locally
            log_line = f"[{percent_int}%] {message}"
            process_logs.append(log_line)
            
            # Update database
            conn = sqlite3.connect(db_path, timeout=10.0)
            cursor = conn.cursor()
            cursor.execute('UPDATE scans SET progress_percent = ? WHERE id = ?', (percent_int, scan_id))
            
            # Store logs in database too (so parent can read them)
            logs_json = json.dumps(process_logs)
            cursor.execute('UPDATE scans SET logs = ? WHERE id = ?', (logs_json, scan_id))
            
            conn.commit()
            conn.close()
        except Exception as e:
            # If callback fails, log it but don't crash the scan
            error_line = f"[ERROR in progress_callback] {str(e)}"
            process_logs.append(error_line)
            process_logs.append(traceback.format_exc())
    
    def import_json_inline(json_file: str) -> int:
        """Import JSON results to database (inline version for worker process)."""
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Insert analysis run
        metadata = data['metadata']
        universal_coverage = metadata.get('universalCoverage', {})
        filter_statistics = metadata.get('filterStatistics', {})
        
        identities_with_gaps = universal_coverage.get('identities_with_gaps')
        
        cursor.execute('''
            INSERT INTO analysis_runs (generated_at, tenant_id, total_permutations, gaps, excluded_policies_count, json_file, version,
                                       total_identities, mfa_coverage_pct, auth_strength_coverage_pct, block_coverage_pct, identities_with_gaps,
                                       included_users_count, excluded_users_count, analysis_duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metadata['generatedAt'],
            metadata.get('tenantId'),
            metadata['totalPermutations'],
            metadata['gaps'],
            metadata.get('excludedPoliciesCount', 0),
            json_file,
            metadata.get('version', '1.0'),
            universal_coverage.get('total_identities'),
            universal_coverage.get('mfa_coverage_pct'),
            universal_coverage.get('auth_strength_coverage_pct'),
            universal_coverage.get('block_coverage_pct'),
            identities_with_gaps,
            filter_statistics.get('includedUsersCount'),
            filter_statistics.get('excludedUsersCount'),
            metadata.get('analysisDurationSeconds')
        ))
        
        run_id = cursor.lastrowid
        
        # Insert excluded policies
        excluded_policies = data.get('excludedPolicies', [])
        for policy in excluded_policies:
            cursor.execute('''
                INSERT INTO excluded_policies (
                    analysis_run_id, policy_id, display_name, state, reason,
                    created_datetime, modified_datetime, conditions,
                    grant_controls, session_controls
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                policy.get('id'),
                policy.get('displayName'),
                policy.get('state'),
                policy.get('reason'),
                policy.get('createdDateTime'),
                policy.get('modifiedDateTime'),
                json.dumps(policy.get('conditions')) if policy.get('conditions') else None,
                json.dumps(policy.get('grantControls')) if policy.get('grantControls') else None,
                json.dumps(policy.get('sessionControls')) if policy.get('sessionControls') else None
            ))
        
        # Insert permutations
        for result in data['results']:
            perm = result['permutation']
            is_terminated = result.get('terminated', False)
            
            # Dynamically detect identity type (users, agents, or workloadIdentities)
            identity_id = None
            identity_display_name = None
            identity_type = None
            identity_user_count = None
            
            # Get identity information from gap_source (current JSON format)
            gap_source = result.get('gap_source')
            if gap_source:
                identity_id = gap_source.get('id')
                identity_display_name = gap_source.get('displayName')
                identity_type = gap_source.get('type')
            else:
                # Fall back to checking permutation keys directly (critical gap scenario)
                for identity_key in ['users', 'guests', 'agents', 'workloadIdentities']:
                    if identity_key in perm:
                        identity_obj = perm[identity_key]
                        if isinstance(identity_obj, dict):
                            identity_id = identity_obj.get('id')
                            identity_display_name = identity_obj.get('displayName')
                            identity_type = identity_obj.get('type')
                            identity_user_count = identity_obj.get('count')
                            
                            # Map identity_key to proper type if not already set
                            if not identity_type or identity_type == 'all':
                                if identity_key == 'users':
                                    identity_type = 'user'
                                elif identity_key == 'guests':
                                    identity_type = 'guest'
                                elif identity_key == 'agents':
                                    identity_type = 'agent_identity'
                                elif identity_key == 'workloadIdentities':
                                    identity_type = 'workload_identity'
                        elif isinstance(identity_obj, str):
                            identity_id = identity_obj
                            identity_display_name = identity_obj
                            identity_type = 'unknown'
                        break
            
            # Dynamically detect resource type (resourceApps, userActions, or agentResources)
            resource_id = None
            resource_display_name = None
            
            # Check for flat format first (application, userAction fields)
            if 'application' in perm:
                resource_id = perm.get('application')
                resource_display_name = perm.get('application')
            elif 'userAction' in perm:
                resource_id = perm.get('userAction')
                resource_display_name = perm.get('userAction')
            else:
                # Check nested format (resourceApps, userActions, agentResources)
                for resource_key in ['resourceApps', 'userActions', 'agentResources']:
                    if resource_key in perm:
                        resource_obj = perm[resource_key]
                        if isinstance(resource_obj, dict):
                            resource_id = resource_obj.get('id')
                            resource_display_name = resource_obj.get('displayName')
                        elif isinstance(resource_obj, str):
                            # Handle simple string values like "all"
                            resource_id = resource_obj
                            resource_display_name = resource_obj
                        break
            
            # Extract count values from permutation dimensions (for critical gap scenarios)
            resource_app_count = None
            location_count = None
            client_app_type_count = None
            
            for resource_key in ['resourceApps', 'userActions', 'agentResources']:
                if resource_key in perm and isinstance(perm[resource_key], dict):
                    count_value = perm[resource_key].get('count')
                    # Keep numeric counts, convert 'all' string to None
                    if count_value is not None and count_value != 'all':
                        resource_app_count = count_value
                    break
            
            locations_obj = perm.get('locations')
            if isinstance(locations_obj, dict):
                count_value = locations_obj.get('count')
                # Keep numeric counts, convert 'all' string to None
                if count_value is not None and count_value != 'all':
                    location_count = count_value
            
            client_app_types_obj = perm.get('clientAppTypes')
            if isinstance(client_app_types_obj, dict):
                count_value = client_app_types_obj.get('count')
                # Keep numeric counts, convert 'all' string to None
                if count_value is not None and count_value != 'all':
                    client_app_type_count = count_value
            
            # Check if this is a universal gap
            is_universal_gap = result.get('is_universal_gap', False)
            
            cursor.execute('''
                INSERT INTO permutations (
                    analysis_run_id, user_id, user_display_name, user_type, user_count,
                    resource_app_id, resource_app_name, client_app_type, platform,
                    location_id, location_name, lineage, terminated,
                    resource_app_count, location_count, client_app_type_count, is_universal_gap
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                identity_id,
                identity_display_name,
                identity_type,
                identity_user_count if identity_user_count is not None else None,
                resource_id,
                resource_display_name,
                perm.get('clientAppType') if 'clientAppType' in perm else (perm.get('clientAppTypes', {}).get('id') if isinstance(perm.get('clientAppTypes'), dict) else perm.get('clientAppTypes')),
                perm.get('platform') if 'platform' in perm else perm.get('platforms'),
                perm.get('location') if 'location' in perm else (perm.get('locations', {}).get('id') if isinstance(perm.get('locations'), dict) else perm.get('locations')),
                perm.get('location') if 'location' in perm else (perm.get('locations', {}).get('displayName') if isinstance(perm.get('locations'), dict) else perm.get('locations')),
                result.get('lineage'),
                1 if is_terminated else 0,
                resource_app_count,
                location_count,
                client_app_type_count,
                1 if is_universal_gap else 0
            ))
        
        conn.commit()
        conn.close()
        
        return run_id
    
    try:
        process_logs.append(f"=== Starting scan #{scan_id} in process {os.getpid()} ===")
        process_logs.append(f"Configuration: {config}")
        
        result = run_analysis(token, config, progress_callback, source='web')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if result['success']:
            # Import the JSON results to get analysis_run_id
            analysis_run_id = import_json_inline(result['result_path'])
            
            # Extract tenant ID and domain from result metadata
            result_json_path = Path(result['result_path'])
            with open(result_json_path, 'r', encoding='utf-8') as f:
                result_json = json.load(f)
            tenant_id = result_json.get('metadata', {}).get('tenantId')
            tenant_domain = result_json.get('metadata', {}).get('primaryDomain')
            
            process_logs.append(f"Tenant: {tenant_id}")
            if tenant_domain:
                process_logs.append(f"Domain: {tenant_domain}")
            
            # Update scan record
            cursor.execute('''
                UPDATE scans 
                SET status = 'completed',
                    completed_at = ?,
                    result_path = ?,
                    permutation_count = ?,
                    progress_percent = 100,
                    analysis_run_id = ?,
                    logs = ?,
                    tenant_id = ?,
                    tenant_domain = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), result['result_path'], 
                  result['permutations_count'], analysis_run_id, 
                  json.dumps(process_logs), tenant_id, tenant_domain, scan_id))
            
            process_logs.append("=== Scan completed successfully ===")
        else:
            # Log the error before updating database
            error_msg = result.get('error', 'Unknown error')
            process_logs.append(f"=== Scan FAILED ===")
            process_logs.append(f"ERROR: {error_msg}")
            
            cursor.execute('''
                UPDATE scans 
                SET status = 'failed',
                    completed_at = ?,
                    error = ?,
                    logs = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), error_msg, 
                  json.dumps(process_logs), scan_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        
        process_logs.append("=== Scan FAILED with exception ===")
        process_logs.append(f"ERROR: {error_msg}")
        process_logs.append("Traceback:")
        process_logs.append(traceback_str)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans 
            SET status = 'failed',
                completed_at = ?,
                error = ?,
                logs = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), f"{error_msg}\n{traceback_str}", 
              json.dumps(process_logs), scan_id))
        conn.commit()
        conn.close()
    
    # CRITICAL: Explicitly exit the worker process to ensure it terminates
    # Without this, the process may hang due to lingering threads or resources
    sys.exit(0)


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear cache based on specified mode."""
    try:
        data = request.json or {}
        mode = data.get('mode', 'all')
        
        # Validate mode
        if mode not in ['all', 'policies', 'tenant']:
            return jsonify({'error': f'Invalid cache clearing mode: {mode}. Must be "all", "policies", or "tenant"'}), 400
        
        # Use mapper to clear cache
        # We don't need a token for cache clearing, just create a dummy client
        from caInsight.analyzer.mapper import UserMapper
        dummy_client = None  # Mapper only needs api_client for fetching, not for clearing
        mapper = UserMapper(dummy_client)
        mapper.clear_mapping_cache(mode=mode)
        
        cache_type = {'all': 'all caches', 'policies': 'policy caches', 'tenant': 'tenant caches'}.get(mode, 'cache')
        return jsonify({
            'success': True,
            'message': f'Successfully cleared {cache_type}'
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to clear cache: {str(e)}'
        }), 500


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans."""
    # Periodic cleanup: Remove all terminated processes from tracking
    global scan_processes
    dead_scan_ids = []
    for sid, proc in scan_processes.items():
        if not proc.is_alive():
            proc.join(timeout=0.1)  # Reap the process
            dead_scan_ids.append(sid)
    
    for sid in dead_scan_ids:
        del scan_processes[sid]
        print(f"[CLEANUP] Removed terminated process for scan {sid}")
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            s.*,
            ar.tenant_id,
            ar.included_users_count,
            ar.excluded_users_count,
            ar.total_identities_in_tenant
        FROM scans s
        LEFT JOIN analysis_runs ar ON s.analysis_run_id = ar.id
        ORDER BY s.started_at DESC
        LIMIT 50
    ''')
    
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(scans)


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get details for a specific scan."""
    # Clean up completed processes from scan_processes
    if scan_id in scan_processes:
        process = scan_processes[scan_id]
        if not process.is_alive():
            # Process has terminated, clean it up
            process.join(timeout=0.1)  # Reap the process
            del scan_processes[scan_id]
            print(f"[CLEANUP] Removed terminated process for scan {scan_id}")
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(dict(row))


@app.route('/api/scans/start', methods=['POST'])
def start_scan():
    """Start a new scan."""
    data = request.json
    
    # Validate required fields
    if not data.get('token'):
        return jsonify({'error': 'Token is required'}), 400
    
    # Check if there are any running scans
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
    running_count = cursor.fetchone()[0]
    conn.close()
    
    if running_count > 0:
        return jsonify({
            'error': 'A scan is already running. For performance reasons, only one scan can run at a time through the CAInsight portal. Please wait for the current scan to complete.',
            'scan_already_running': True
        }), 409
    
    # Validate token before starting scan
    try:
        client = GraphAPIClient(data['token'])
        is_valid, error_msg = client.validate_token()
        
        if not is_valid:
            return jsonify({
                'error': f'Invalid or expired token: {error_msg}',
                'token_invalid': True
            }), 401
    except Exception as e:
        return jsonify({
            'error': f'Token validation failed: {str(e)}',
            'token_invalid': True
        }), 401
    
    # Build config from request
    config = {
        'assignments': data.get('assignments', 'users'),
        'target_resources': data.get('target_resources', 'cloud-apps'),
        'threads': data.get('threads', 10),
        'clear_cache': data.get('clear_cache')  # Can be None, 'all', 'policies', or 'tenant'
    }
    
    # Handle filter configuration
    filter_cfg = None
    if data.get('filter_config'):
        try:
            filter_cfg = FilterConfig(data['filter_config'])
            # Validate for conflicts
            is_valid, conflicts = filter_cfg.validate()
            if not is_valid:
                conflict_list = ', '.join(conflicts[:5])
                if len(conflicts) > 5:
                    conflict_list += f', ... ({len(conflicts)} total)'
                return jsonify({
                    'error': f'Filter configuration error: {len(conflicts)} ID(s) appear in both include and exclude lists: {conflict_list}'
                }), 400
            config['filter_config'] = filter_cfg
        except Exception as e:
            return jsonify({'error': f'Invalid filter configuration: {str(e)}'}), 400
    
    # Serialize filter config for database storage.
    # Use all raw entries (users + groups + roles) rather than get_include_ids() /
    # get_exclude_ids(), which only return already-resolved user GUIDs at this point —
    # group/role names are resolved later during the scan via resolve_groups_and_roles().
    def _serialize_filter(cfg, attr_users, attr_groups, attr_roles):
        if not cfg:
            return None
        all_entries = sorted(getattr(cfg, attr_users, set()) |
                             getattr(cfg, attr_groups, set()) |
                             getattr(cfg, attr_roles, set()))
        return json.dumps(all_entries) if all_entries else None

    filter_include = _serialize_filter(filter_cfg, 'include_users', 'include_groups', 'include_roles')
    filter_exclude = _serialize_filter(filter_cfg, 'exclude_users', 'exclude_groups', 'exclude_roles')
    
    # Extract tenant_id from token
    tenant_id = None
    try:
        # Decode token to extract tenant_id
        token_parts = data['token'].split('.')
        if len(token_parts) >= 2:
            # Add padding if needed
            payload = token_parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding
            decoded = json.loads(base64.urlsafe_b64decode(payload))
            tenant_id = decoded.get('tid')
    except Exception as e:
        print(f"[WARN] Could not extract tenant_id from token: {e}")
    
    # Fetch tenant domain from Microsoft Graph
    tenant_domain = None
    try:
        tenant_domain = get_tenant_primary_domain(data['token'])
        if tenant_domain:
            print(f"[INFO] Retrieved tenant domain: {tenant_domain}")
    except Exception as e:
        print(f"[WARN] Could not fetch tenant domain: {e}")
        # Don't fail the scan start if domain fetch fails
    
    # Create scan record
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (
            status, assignments, target_resources, conditions,
            threads, include_object_ids, skip_object_ids, started_at, progress_percent, tenant_id, tenant_domain
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        'running',
        config['assignments'],
        config['target_resources'],
        json.dumps(config.get('conditions', [])),
        config.get('threads', 10),
        filter_include,
        filter_exclude,
        datetime.now().isoformat(),
        0,
        tenant_id,
        tenant_domain
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Initialize log storage
    scan_logs[scan_id] = []
    
    # Start background process (not thread!)
    process = run_scan_background(scan_id, data['token'], config)
    print(f"[START] Started scan {scan_id} in process {process.pid}")
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'running',
        'message': 'Scan started successfully',
        'pid': process.pid
    }), 201


@app.route('/api/scans/<int:scan_id>/progress')
def scan_progress(scan_id):
    """Server-Sent Events endpoint for real-time progress updates."""
    def generate():
        """Generate SSE stream."""
        yield f"data: {json.dumps({'connected': True, 'scan_id': scan_id})}\n\n"
        
        # Stream progress updates
        while True:
            if scan_id in active_scans:
                progress = active_scans[scan_id]
                yield f"data: {json.dumps(progress)}\n\n"
                
                if progress['percent'] == 100 or 'Failed' in progress.get('message', ''):
                    time.sleep(1)
                    break
            else:
                # Check database for scan status
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
                scan = cursor.fetchone()
                conn.close()
                
                if scan:
                    status_data = {
                        'percent': scan['progress_percent'],
                        'message': scan['status'],
                        'timestamp': datetime.now().isoformat()
                    }
                    yield f"data: {json.dumps(status_data)}\n\n"
                    
                    if scan['status'] in ['completed', 'failed']:
                        time.sleep(1)
                        break
            
            time.sleep(0.5)
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/scans/<int:scan_id>/logs')
def scan_logs_stream(scan_id):
    """Server-Sent Events endpoint for real-time log streaming."""
    def generate():
        """Generate SSE stream of scan logs."""
        global scan_logs
        
        # Send initial connection message
        yield f"data: {json.dumps({'connected': True, 'scan_id': scan_id})}\n\n"
        
        last_line_sent = 0
        
        # Stream log lines
        while True:
            # Always read from database (worker process updates DB, not parent's scan_logs)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT logs FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            conn.close()
            
            logs = []
            if row and row[0]:
                try:
                    logs = json.loads(row[0])
                except:
                    logs = []
            
            # Send new lines since last check
            while last_line_sent < len(logs):
                line = logs[last_line_sent]
                yield f"data: {json.dumps({'line': line})}\n\n"
                last_line_sent += 1
            
            # Check if scan is complete
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT status, progress_percent FROM scans WHERE id = ?', (scan_id,))
            scan = cursor.fetchone()
            conn.close()
            
            if scan and scan['status'] in ['completed', 'failed', 'cancelled']:
                # Send final logs and completion message
                time.sleep(0.5)
                yield f"data: {json.dumps({'complete': True, 'status': scan['status']})}\n\n"
                break
            
            time.sleep(0.3)
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/scans/<int:scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan and FORCEFULLY TERMINATE if running (multiprocessing approach)."""
    global scan_logs, active_scans, scan_processes
    
    # AGGRESSIVE: Terminate the process if it's running
    if scan_id in scan_processes:
        process = scan_processes[scan_id]
        try:
            if process.is_alive():
                print(f"[DELETE] Terminating process {process.pid} for scan {scan_id}")
                # Force terminate the process (SIGTERM on Unix, TerminateProcess on Windows)
                process.terminate()
                # Wait up to 1 second for graceful termination
                process.join(timeout=1.0)
                
                # If still alive, kill it even more aggressively
                if process.is_alive():
                    print(f"[DELETE] Process still alive, sending SIGKILL to {process.pid}")
                    process.kill()
                    process.join(timeout=0.5)
                    
                    # Last resort: On Windows, use taskkill
                    if process.is_alive():
                        print(f"[DELETE] Using taskkill on {process.pid}")
                        try:
                            subprocess.run(['taskkill', '/F', '/PID', str(process.pid)], 
                                         capture_output=True, timeout=2)
                        except:
                            pass
                
                print(f"[DELETE] Process {process.pid} terminated successfully")
            else:
                print(f"[DELETE] Process for scan {scan_id} already dead")
        except Exception as e:
            print(f"[DELETE] Error terminating process: {e}")
        finally:
            del scan_processes[scan_id]
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        return jsonify({'error': 'Scan not found'}), 404
    
    # Clean up logs and tracking from memory
    if scan_id in scan_logs:
        del scan_logs[scan_id]
    if scan_id in active_scans:
        del active_scans[scan_id]
    
    # Mark as cancelled in database if it was running
    if scan['status'] == 'running':
        cursor.execute('''
            UPDATE scans 
            SET status = 'cancelled',
                completed_at = ?,
                error = 'Forcefully terminated by user'
            WHERE id = ?
        ''', (datetime.now().isoformat(), scan_id))
        conn.commit()
    
    # Delete result files if they exist
    if scan['result_path']:
        try:
            Path(scan['result_path']).unlink(missing_ok=True)
            html_path = Path(scan['result_path']).replace('.json', '.html')
            Path(html_path).unlink(missing_ok=True)
        except Exception:
            pass
    
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Scan deleted and process terminated'})



# ============================================================================
# END SCAN MANAGEMENT ENDPOINTS
# ============================================================================


def main():
    """Main entry point for the API server"""
    # Ensure we're in the correct directory (project root)
    if not Path('caInsight').exists():
        print("Error: Must run from project root directory")
        print("Usage: python web/api_server.py")
        exit(1)
    
    init_db()
    
    # Start server
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    print(f"\n{'='*60}")
    print(f"CA Insight API Server")
    print(f"{'='*60}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)


if __name__ == '__main__':
    # Required for multiprocessing on Windows
    multiprocessing.freeze_support()
    main()

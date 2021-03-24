####
# This script contains functions that create new projects and adds
# specific pre-defined permissions for pre-defined groups at the Project, 
# Default Workbook, and Default Datasoure levels. 
#
# Created by: Christopher Wilbar
# Version 1.0 - 9/10/2019
# Portions of script pulled from:
# https://github.com/tableau/server-client-python/blob/master/samples/create_project.py
# https://github.com/tableau/rest-api-samples/blob/master/python/update_permission.py
#
# To run the script, you must have installed Python 3.0 or later,
# plus the following libraries/packages: 
#   'tableauserverclient'  https://tableau.github.io/server-client-python/docs/
#   'requests'             http://docs.python-requests.org/en/latest/  
#   'pyyaml'               https://pyyaml.org/wiki/PyYAMLDocumentation
#
# 
# This script requires a .yaml configuration file with the following mappings:
# serverUrl:           Tableau Server address (e.g. https:\\10ax.online.tableau.com)
# apiVersion:          API Version supported by Tableau Server. Originally built and testing using "3.4"
#                         - see https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_concepts_versions.htm
# site:                Tableau Server Site Name to modify. Can be "" if updating default site.
# adminUser:           User name with server administrator permission
# adminPwd:            Password for adminUser
# contentPermission:   One of 'LockedToProject' or 'ManagedByOwner'
#                         - see https://help.tableau.com/current/server/en-us/permissions_project_lock.htm
# updateGroups:        Exact Group Names on Tableau Server to permission for specified projects
#                         - see permisisons variable in script for current supported groups
# projectNames:        Sequence of Names of Projects to Create
#
# The script takes in the filepath to the .yaml configuration file as a required argument.
#
#
# WARNING: This script will not remove/change any existing permisisons on Tableau Server. It will only add
# new permissions if they do not exist.
####

import tableauserverclient as TSC # Contains methods for optimized connected to Tableau Server REST API
import requests # Contains methods used to make HTTP requests
import yaml # Contains methods to read and interpret .yaml files
import xml.etree.ElementTree as ET # Contains methods used to build and parse XML
import sys
#import logging


#import datetime
#start_time = datetime.datetime.now()
#print("Start time: ",str(datetime.datetime.now()))

# The namespace for the REST API is 'http://tableausoftware.com/api' for Tableau Server 9.0
# or 'http://tableau.com/api' for Tableau Server 9.1 or later
xmlns = {'t': 'http://tableau.com/api'}

# Define Permissions for each pre-defined Tableau group here
permissions = {
               "Server Admins - Tab":{'project':['ProjectLeader'],
                                      'workbook':['AddComment','ChangeHierarchy','ChangePermissions','Delete','ExportData','ExportImage',
                                                 'ExportXml','Filter','Read','ShareView','ViewComments','ViewUnderlyingData','WebAuthoring',
                                                 'Write'],
                                      'datasource':['ChangePermissions','Connect','Delete','ExportXml','Read','Write']
                                     },
               
               "Creators - Tab":{'project':['ProjectLeader'],
                                      'workbook':['AddComment','ChangeHierarchy','Delete','ExportData','ExportImage',
                                                 'ExportXml','Filter','Read','ShareView','ViewComments','ViewUnderlyingData','WebAuthoring',
                                                 'Write'],
                                      'datasource':['ChangePermissions','Connect','Delete','ExportXml','Read','Write']
                                    },
               
               "Training Web Developers - Tab":{'project':['Read'],
                                                'workbook':['ExportImage','Filter','Read','ShareView','WebAuthoring','Write'],
                                                'datasource':['Connect','Read']
                                               }
               
              }


class ApiCallError(Exception):
    pass


class InputError(Exception):
    pass


def _encode_for_display(text):
    """
    Encodes strings so they can display as ASCII in a Windows terminal window.
    This function also encodes strings for processing by xml.etree.ElementTree functions.
    Returns an ASCII-encoded version of the text.
    Unicode characters are converted to ASCII placeholders (for example, "?").
    """
    return text.encode('ascii', errors="backslashreplace").decode('utf-8')


def _check_status(server_response, success_code):
    """
    Checks the server response for possible errors.
    'server_response'       the response received from the server
    'success_code'          the expected success code for the response
    Throws an ApiCallError exception if the API call fails.
    """
    if server_response.status_code != success_code:
        parsed_response = ET.fromstring(server_response.text)

        # Obtain the 3 xml tags from the response: error, summary, and detail tags
        error_element = parsed_response.find('t:error', namespaces=xmlns)
        summary_element = parsed_response.find('.//t:summary', namespaces=xmlns)
        detail_element = parsed_response.find('.//t:detail', namespaces=xmlns)

        # Retrieve the error code, summary, and detail if the response contains them
        code = error_element.get('code', 'unknown') if error_element is not None else 'unknown code'
        summary = summary_element.text if summary_element is not None else 'unknown summary'
        detail = detail_element.text if detail_element is not None else 'unknown detail'
        error_message = '{0}: {1} - {2}'.format(code, summary, detail)
        raise ApiCallError(error_message)
    return

def sign_in(server, api_version, username, password, site):
    """
    Signs in to the server specified with the given credentials
    'server'        specified server address
    'api_version'   supported REST API version
    'username'      the name (not ID) of the user to sign in as
    'password'      the password for the user
    'site'          the ID (as a string) of the site on the server to sign in to 
    Returns dictionary with server, api_version, auth_token, and site_id key/value pairs
    """
    url = server + "/api/{0}/auth/signin".format(api_version)

    # Builds the request
    xml_request = ET.Element('tsRequest')
    credentials_element = ET.SubElement(xml_request, 'credentials', name=username, password=password)
    ET.SubElement(credentials_element, 'site', contentUrl=site)
    xml_request = ET.tostring(xml_request)

    # Make the request to server
    server_response = requests.post(url, data=xml_request)
    _check_status(server_response, 200)

    # ASCII encode server response to enable displaying to console
    server_response = _encode_for_display(server_response.text)

    # Reads and parses the response
    parsed_response = ET.fromstring(server_response)

    # Gets the auth token and site ID
    token = parsed_response.find('t:credentials', namespaces=xmlns).get('token')
    site_id = parsed_response.find('.//t:site', namespaces=xmlns).get('id')
    connection = {"server":server,"api_version":api_version,"auth_token":token,"site_id":site_id}
    return connection


def sign_out(connection):
    """
    Destroys the active session and invalidates authentication token.
    'connection' is a dictionary with at least the following key/value pairs:
        'server'        specified server address
        'auth_token'    authentication token that grants user access to API calls
        'api_version'   supported REST API version
    """
    url = connection['server'] + "/api/{0}/auth/signout".format(connection['api_version'])
    server_response = requests.post(url, headers={'x-tableau-auth': connection['auth_token']})
    _check_status(server_response, 204)
    return

def query_permission(connection, project_id, group_id, permission_type):
    """
    Returns a list of all project level permissions for the specified user.
    'server'        specified server address
    'auth_token'    authentication token that grants user access to API calls
    'site_id'       ID of the site that the user is signed into
    'workbook_id'   ID of workbook to update permission in
    'user_id'       ID of the user to update
    """
    if permission_type == 'project':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/permissions".format(connection['api_version'], connection['site_id'], project_id)
    elif permission_type == 'workbook' or permission_type == 'datasource':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/default-permissions/{3}s".format(connection['api_version'], connection['site_id'], project_id, permission_type)
    else:
        error = 'Invalid permission type entered: \"%s\".'
        raise InputError(error % permission_type)
    
    server_response = requests.get(url, headers={'x-tableau-auth': connection['auth_token']})
    _check_status(server_response, 200)
    server_response = _encode_for_display(server_response.text)

    # Reads and parses the response
    parsed_response = ET.fromstring(server_response)

    # Find all the capabilities for a specific group
    granteecapabilities = parsed_response.findall('.//t:granteeCapabilities', namespaces=xmlns)
    all_capabilities = {}
    for capability in granteecapabilities:
        group = capability.find('.//t:group', namespaces=xmlns)
        if group is not None and group.get('id') == group_id:
            capabilities = capability.findall('.//t:capability', namespaces=xmlns)
            for capability in capabilities:
                all_capabilities.update( {capability.get('name'):capability.get('mode')})
            return all_capabilities
        
def add_permission(connection, project_id, group_id, permission_type, permission_list):
    """
    Adds the specified permissions of the specified type to the specified group on the specified project.
    Permission mode set to Allow. Modify function if Deny required.
    'connection' is a dictionary with at least the following key/value pairs:
        'server'        specified server address
        'auth_token'    authentication token that grants user access to API calls
        'api_version'   supported REST API version
        'site_id'       ID of the site that the user is signed into
    'project_id'        ID of project to update permission in
    'group_id'          ID of the group to update
    'permission_type'   one of 'project','workbook',or 'datasource' for which type of permisison to be added
    'permission_list'   list of permissions to add or update
    """
    
    if permission_type == 'project':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/permissions".format(connection['api_version'], connection['site_id'], project_id)
    elif permission_type == 'workbook' or permission_type == 'datasource':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/default-permissions/{3}s".format(connection['api_version'], connection['site_id'], project_id, permission_type)
    else:
        error = 'Invalid permission type entered: \"%s\".'
        raise InputError(error % permission_type)
    
    # Build the request
    xml_request = ET.Element('tsRequest')
    permissions_element = ET.SubElement(xml_request, 'permissions')
    grantee_element = ET.SubElement(permissions_element, 'granteeCapabilities')
    ET.SubElement(grantee_element, 'group', id=group_id)
    capabilities_element = ET.SubElement(grantee_element, 'capabilities')
    if isinstance(permission_list, list): 
        for permission in permission_list:
            ET.SubElement(capabilities_element, 'capability', name=permission, mode="Allow")
    else:
        ET.SubElement(capabilities_element, 'capability', name=permission_list, mode="Allow")    
    xml_request = ET.tostring(xml_request)

    server_request = requests.put(url, data=xml_request, headers={'x-tableau-auth': connection['auth_token']})
    _check_status(server_request, 200)
    return


def delete_permission(connection, project_id, group_id, permisison_type, permission_list, existing_mode):
    """
    Deletes a specific permission from the workbook.
    'server'            specified server address
    'auth_token'        authentication token that grants user access to API calls
    'site_id'           ID of the site that the user is signed into
    'workbook_id'       ID of workbook to update permission in
    'user_id'           ID of the user to update
    'permission_name'   name of permission to update
    'existing_mode'     is the existing mode for the permission
    """
    
    if permission_type == 'project':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/permissions/groups/{3}/{4}/{5}".format(connection['api_version'],
                                                                                           connection['site_id'],
                                                                                           project_id,
                                                                                           group_id,
                                                                                           permission_list,
                                                                                           existing_mode)
    elif permission_type == 'workbook' or permission_type == 'datasource':
        url = connection['server'] + "/api/{0}/sites/{1}/projects/{2}/default-permissions/{3}s/groups/{4}/{5}/{6}".format(connection['api_version'],
                                                                                           connection['site_id'],
                                                                                           project_id,
                                                                                           permission_type,
                                                                                           group_id,
                                                                                           permission_list,
                                                                                           existing_mode)
    else:
        error = 'Invalid permission type entered: \"%s\".'
        raise InputError(error % permission_type)
    
    server_response = requests.delete(url, headers={'x-tableau-auth': connection['auth_token']})
    _check_status(server_response, 204)
    return

 
def main():
    
    ##### STEP 0: Initialization #####
    # Check file path to yaml given
    if len(sys.argv) != 2:
        error = "Filepath needed for .yaml document"
        raise InputError(error)
    
    filepath_yaml = sys.argv[1]
    
    #print("Loading parameters from \"%s\"" % filepath_yaml)
    
    # Import Parameters from yaml file for script
    
    try:
        tab_vars = yaml.safe_load(open(filepath_yaml))
    except Exception as e:
        error = 'Could not create parameters from yaml file. Check format of document and try again.'
        raise InputError(error)
    
    # Check permission list exists for groups entered
    if tab_vars['updateGroups'] is not None:
        invalidgroups = set(tab_vars['updateGroups'])-set(permissions)
        if invalidgroups:
            error = 'Permission list does not exist for groups: %s'
            raise InputError(error % invalidgroups)
        
    
    ##### STEP 1: Project Creation #####
    
    #First need to get API connection directly
    try:
        connection = sign_in(tab_vars['serverUrl'], tab_vars['apiVersion'], tab_vars['adminUser'], tab_vars['adminPwd'], tab_vars['site'])
    except Exception as e:
        error = "Unable to connect to Tableau Server. Double-check credentials and try again."
        raise ApiCallError(error)
    
    # Use TSC to Create Projects
    
    #Define variables to create TSC connection:
    tableau_auth = TSC.TableauAuth(tab_vars['adminUser'], tab_vars['adminPwd'], tab_vars['site'])
    server = TSC.Server(tab_vars['serverUrl'])  

    #Create with loop to login with TSC and log out once complete or error
    with server.auth.sign_in(tableau_auth):
        server.use_server_version()
        
        #Get group Info which will be needed later
        existingGroups = {}
        all_groups = list(TSC.Pager(server.groups))
        for group in all_groups:
            existingGroups.update( {group.name:group.id})
        
        #Create empty list of Project Ids and Empty Set of Project Names
        existingProjects = {}
        
        #Get project name and project id of all existing projects on the Server
        existing_project_items = list(TSC.Pager(server.projects))

        for proj in existing_project_items :
            existingProjects.update({proj.name:proj.id})
 
        counter = 0
        total_project_count = len(tab_vars['projectNames'])
 
        for project in tab_vars['projectNames']:
            if counter/total_project_count*100 %10 == 0:
                print(counter/total_project_count*100,"% done")
            counter+=1
            if project in existingProjects:
                project_id = existingProjects[project]
            else:
                project_item = TSC.ProjectItem(name=project, content_permissions=tab_vars['contentPermission'])
                new_project = server.projects.create(project_item)
                project_id = new_project.id
                
            if tab_vars['updateGroups'] is not None:
                for group in range(len(tab_vars['updateGroups'])):
                    groupID = existingGroups[tab_vars['updateGroups'][group]]
                    for permission_type in ['project','workbook','datasource']:
                        permissions_desired = permissions[tab_vars['updateGroups'][group]][permission_type]
                        if permissions_desired is not None:
                            add_permission(connection, project_id, groupID, permission_type, permissions_desired)
            
            

    ##### STEP 3: Sign out #####
    #print("\n3. Signing out and invalidating the authentication token")
    sign_out(connection)
    
    #end_time = datetime.datetime.now()
    #print("End time: ", str(end_time))
    #print("Elapsed time: ", str(end_time-start_time))

if __name__ == "__main__":
    main()        

#!/usr/bin/python3
##
# Demo utility that shows how a MongoDB Atlas organisation's configuration can be retrieved, stored
# in a database and then analysed for non-compliances.
#
# Prerequisites:
# * A MongoDB Atlas organisation (and associated projects & clusters) has been configured
# * This script ('atlas-org-config-checker.py') is executable on the host OS
# * The dependency MongoDB Python Driver (PyMongo) has been installed, eg:
#  $ pip3 install --user pymongo
#
# To see how to use the script, first run it with the 'help' parameter:
#  $ ./atlas-org-config-checker.py -h
#
# Example to execute the script passing in public and private API keys for the Atlas org:
#  $ ./atlas-org-config-checker.py -k "dttwone" -p "8e1-ed32-38d-380-33847" -o "bb73cf83ab233329"
##
import sys
import argparse
import requests
import re
from collections import namedtuple
from requests.auth import HTTPDigestAuth
from datetime import datetime
from pprint import pprint
from pymongo import MongoClient, DESCENDING


# Named tuple to capture information about a non-compliance
ClusterNonCompliance = namedtuple("ClusterNonCompliance", [
                                    "orgId", "orgName", "projectId", "projectName", "clusterId",
                                    "clusterName", "description", "badValue"
                                 ])
AccessListNonCompliance = namedtuple("AccessListNonCompliance", [
                                        "orgId", "orgName", "projectId", "projectName",
                                        "cidrBlock", "comment", "description", "badValue"
                                    ])


##
# Main function to parse passed-in process before invoking the core processing function.
##
def main():
    argparser = argparse.ArgumentParser(description="Demo utility that shows how a MongoDB Atlas "
                                        "organisation's configuration can be retrieved, stored in "
                                        "a database and then analysed for non-compliances.")
    argparser.add_argument("-k", "--atlasApiPubKey",
                           help=f"Atlas Admin API Organisation Public Key")
    argparser.add_argument("-p", "--atlasApiPrvKey",
                           help=f"Atlas Admin API Organisation Private Key")
    argparser.add_argument("-o", "--atlasOrgId",
                           help=f"Atlas Organisation Id")
    argparser.add_argument("-u", "--url", default=DEFAULT_MONGODB_URL,
                           help=f"MongoDB cluster URL (default: {DEFAULT_MONGODB_URL})")
    argparser.add_argument("-d", "--db", default=DEFAULT_DBNAME,
                           help=f"Database name (default: {DEFAULT_DBNAME})")
    argparser.add_argument("-c", "--coll", default=DEFAULT_COLLNAME,
                           help=f"Collection name (default: {DEFAULT_COLLNAME})")
    args = argparser.parse_args()
    start = datetime.now()
    run(args.atlasApiPubKey, args.atlasApiPrvKey, args.atlasOrgId, args.url, args.db, args.coll)
    end = datetime.now()
    print(f"\nFinished processing in {int((end-start).total_seconds())} seconds")
    print()


##
# Retrieve Atlas org config, save to DB and report non-compliances.
##
def run(publicKey, privateKey, orgId, url, dbname, collname):
    coll = getDBCollumnHandle(url, dbname, collname)

    if DO_DB_DATA_COLLECT:
        fullConfig = getFullConfigFromAtlasAdminAPI(publicKey, privateKey, orgId)
        insertFullConfigIntoDB(coll, fullConfig)

    searchForClusterNonCompliances(coll)


##
# Retrieve Atlas org config using various Atlas Admin API calls.
##
def getFullConfigFromAtlasAdminAPI(publicKey, privateKey, orgId):
    print(f"\nConnecting to Atlas Admin API to retrieve resources for organisation id: '{orgId}'")

    fullConfig = {
        TIMESTAMP_JSON_KEY: datetime.utcnow(),
        "publicAPIKeyUsed": publicKey,
        "orgId": orgId,
    }

    startOrgResource = f"{BASE_ATLAS_ADMIN_URL}/orgs/{orgId}"
    fullConfig["org"] = getConfigResource(publicKey, privateKey, startOrgResource, 1)
    print()
    # pprint(fullConfig)
    return fullConfig


##
# Recursive functuon to get a specific Atlas resource using a specific REST API resource.
##
def getConfigResource(publicKey, privateKey, startLink, level):
    if level >= INFINITE_RECURSION_LEVEL_THRESHOLD:
        sys.exit(f"\nERROR: Infinite recursion detected, while traversing the Atlas Admin API "
                 f"resources'\n")

    response = requests.get(startLink, auth=HTTPDigestAuth(publicKey, privateKey),
                            params=FIXED_QUERY_PARAMS)

    if response.status_code != 200:
        sys.exit(f"\nERROR: Call to '{startLink}' returned a non-OK status code: '"
                 f"{response.status_code}: {response.reason}'\n")

    responseJson = response.json()
    print(".", end="", flush=True)
    newLevel = level + 1

    # If API response contains "links" section in addition to "results" section, follow the links
    if LINKS_JSON_KEY in responseJson:
        for link in responseJson[LINKS_JSON_KEY]:
            if HREF_LINK_JSON_KEY not in link or REL_LINK_JSON_KEY not in link:
                sys.exit(f"\nERROR: Link to resource does not contain a '{HREF_LINK_JSON_KEY}' or"
                         f" '{REL_LINK_JSON_KEY}' field, content: {link}\n")

            # e.g. match "user" in https://cloud.mongodb.com/api/atlas/v1.0/users/$d2737e579358e3
            linkResourceMatch = re.match(r"http://cloud.mongodb.com/([^/]*)",
                                         link[REL_LINK_JSON_KEY])

            # Inline the content of each invokved link
            if linkResourceMatch:
                linkResourceType = linkResourceMatch.group(1)
                # Via API get main config for the set of child resources the link was provided for
                childConfigs = getConfigResource(publicKey, privateKey, link[HREF_LINK_JSON_KEY],
                                                 newLevel)
                # Some resources may related to other resources from a hard-coded relationship
                # (not provided in links responses, so go and bring them in too where relevant
                addRelatedChildConfigResources(publicKey, privateKey, linkResourceType,
                                               childConfigs, newLevel)

                # Rename 'groups' resource to 'projects'
                if linkResourceType == PROJECT_RESOURCES_ALIAS:
                    resourceTypeKey = PROJECT_RESOURCES_NAME
                else:
                    resourceTypeKey = linkResourceType

                if resourceTypeKey not in responseJson:
                    responseJson[resourceTypeKey] = []

                # Take each hild element and attach it to the parent JSON
                for childConfig in childConfigs[RESULTS_JSON_KEY]:
                    if LINKS_JSON_KEY in childConfig:
                        del childConfig[LINKS_JSON_KEY]

                    responseJson[resourceTypeKey].append(childConfig)

        # Remove the old links now as the data from the link has been retrieved
        del responseJson[LINKS_JSON_KEY]

    return responseJson


##
# If the Atlas resource has some other resources that actually belong to it, grab them.
##
def addRelatedChildConfigResources(publicKey, privateKey, parentType, parentConfigs, level):
    if RESULTS_JSON_KEY not in parentConfigs:
        return

    # Get the extra stuff that should hang off Projects (aka Groups) resources
    if parentType == PROJECT_RESOURCES_ALIAS:
        for project in parentConfigs[RESULTS_JSON_KEY]:
            projectId = project[ID_JSON_FIELD]

            # Loop thru well know sub-resource types to grab
            for resource in GROUP_SUB_RESOURCES:
                if resource not in project:
                    project[resource] = []

                # Get sub-resource via separate API call
                targetURL = f"{BASE_ATLAS_ADMIN_URL}/{parentType}/{projectId}/{resource}"
                childConfigs = getConfigResource(publicKey, privateKey, targetURL, level)

                # Unpick each sub-resource and attach it to the parent
                if RESULTS_JSON_KEY in childConfigs:
                    for childConfig in childConfigs[RESULTS_JSON_KEY]:
                        if LINKS_JSON_KEY in childConfig:
                            del childConfig[LINKS_JSON_KEY]

                        # If resource is a cluster, add "proxessArg" advanced settings config data
                        if resource == CLUSTERS_RESOURCES_NAME:
                            clusterName = childConfig[NAME_JSON_FIELD]
                            advClsTargetURL = f"{targetURL}/{clusterName}/{PROCESS_ARGS_JSON_FIELD}"
                            advancedClusterConfig = getConfigResource(publicKey, privateKey,
                                                                      advClsTargetURL, level)
                            childConfig[PROCESS_ARGS_JSON_FIELD] = advancedClusterConfig

                        project[resource].append(childConfig)


##
# Get a MongoDB Client connection and then a specific database collection it holds.
##
def getDBCollumnHandle(url, dbname, collname):
    print(f"\nConnecting to MongoDB using URL '{url}' to locate collection '{dbname}.{collname}'")
    connection = MongoClient(url)
    coll = connection[dbname][collname]
    coll.create_index([(TIMESTAMP_JSON_KEY, DESCENDING)])  # Ensure index exists
    return coll


##
# Insert retrieved Atlas org configuration into a database collection.
##
def insertFullConfigIntoDB(coll, fullConfig):
    print(f"\nInserting retrieved Atlas configuration for organisation name: "
          f"'{fullConfig['org']['name']}'")
    coll.insert_one(fullConfig)


##
# Analyse latest record Atlas org config stored in DB for violations of various rules.
##
def searchForClusterNonCompliances(coll):
    nonCompliancesList = []

    for checkFunction in CHECK_FUNCTION_LIST:
        nonCompliancesList = mergeLists(nonCompliancesList, checkFunction(coll))

    reportClusterNonCompliances(nonCompliancesList)


##
# Log all the discovered non-compliances.
##
def mergeLists(originalList, newList):
    if newList:
        return originalList + newList
    else:
        return originalList


##
# Log all the discovered non-compliances.
##
def reportClusterNonCompliances(nonCompliancesList):
    print(f"\nReport of non-compliances:\n")
    pprint(nonCompliancesList, indent=3)


##
# NON-COMPLIANCE CHECK: Check for use of banned shared clusters.
##
def checkForBannedSharedClusters(coll):
    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.clusters",
        }},

        {"$match": {
            "org.projects.clusters.providerSettings.instanceSizeName": {"$in": ["M0", "M2", "M5"]},
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "clusterId": "$org.projects.clusters.id",
            "clusterName": "$org.projects.clusters.name",
            "instanceSizeName": "$org.projects.clusters.providerSettings.instanceSizeName",
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "clusterName": 1,
            "instanceSizeName": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        nonCompliancesList.append(ClusterNonCompliance(rec["orgId"], rec["orgName"],
                                                       rec["projectId"], rec["projectName"],
                                                       rec["clusterId"], rec["clusterName"],
                                                       "Using banned cluster type",
                                                       rec["instanceSizeName"]))

    return nonCompliancesList


##
# NON-COMPLIANCE CHECK: Check for use of access lists for projects that are too open to to many IP
# addresses.
##
def checkForTooOpenProjectAccessLists(coll):
    subnetThreshold = 16

    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.accessList",
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "cidrBlock": "$org.projects.accessList.cidrBlock",
            "comment": "$org.projects.accessList.comment",
            "subnetMask": {
                "$toInt": {
                    "$first": {
                        "$getField": {
                            "field": "captures", "input": {
                                "$regexFind": {"input": "$org.projects.accessList.cidrBlock",
                                               "regex": r'.*\/(.*)'}
                            }
                        }
                    }
                }
            },
        }},

        {"$match": {
            "subnetMask": {"$lt": subnetThreshold},
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "subnetMask": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        comment = f"{rec['comment']}" if ("comment" in rec) and ({rec['comment']}) \
                                          and (len({rec['comment'].strip()}) > 0) else ""
        nonCompliancesList.append(AccessListNonCompliance(rec["orgId"], rec["orgName"],
                                  rec["projectId"], rec["projectName"], rec["cidrBlock"], comment,
                                  "Using subnet mask which is too open", rec["subnetMask"]))

    return nonCompliancesList


##
# NON-COMPLIANCE CHECK: Check for use of banned cloud providers.
##
def checkForBannedCloudProviders(coll):
    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.clusters",
        }},

        {"$match": {
            "$or": [
                {"org.projects.clusters.providerSettings.providerName": {
                    "$in": ["AZURE", "GCP"]
                }},
                {"org.projects.clusters.providerSettings.backingProviderName": {
                    "$in": ["AZURE", "GCP"]
                }},
            ]
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "clusterId": "$org.projects.clusters.id",
            "clusterName": "$org.projects.clusters.name",
            "providerName": "$org.projects.clusters.providerSettings.providerName",
            "backingProviderName": "$org.projects.clusters.providerSettings.backingProviderName",
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "clusterName": 1,
            "providerName": 1,
            "backingProviderName": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        if "backingProviderName" in rec:
            providerDetails = rec["backingProviderName"]
        else:
            providerDetails = rec["providerName"]

        nonCompliancesList.append(ClusterNonCompliance(rec["orgId"], rec["orgName"],
                                                       rec["projectId"], rec["projectName"],
                                                       rec["clusterId"], rec["clusterName"],
                                                       "Using banned cloud provder",
                                                       providerDetails))

    return nonCompliancesList


##
# NON-COMPLIANCE CHECK: Check for use of risky TLS version (1.0 and 1.1).
##
def checkForRiskyTLSVersions(coll):
    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.clusters",
        }},

        {"$match": {
            "org.projects.clusters.processArgs.minimumEnabledTlsProtocol": {
                "$in": ["TLS1_0", "TLS1_1"]
            },
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "clusterId": "$org.projects.clusters.id",
            "clusterName": "$org.projects.clusters.name",
            "minimumEnabledTlsProtocol":
                "$org.projects.clusters.processArgs.minimumEnabledTlsProtocol",
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "clusterName": 1,
            "minimumEnabledTlsProtocol": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        nonCompliancesList.append(ClusterNonCompliance(rec["orgId"], rec["orgName"],
                                                       rec["projectId"], rec["projectName"],
                                                       rec["clusterId"], rec["clusterName"],
                                                       "Using banned minimum TLS version",
                                                       rec["minimumEnabledTlsProtocol"]))

    return nonCompliancesList


##
# NON-COMPLIANCE CHECK: Check for deployments in specific regions of specific cloud providers which
# are banned.
##
def checkForBannedRegionsInCloudProviders(coll):
    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.clusters",
        }},

        {"$match": {
            "$or": [
                {"$and": [
                    {"$or": [
                        {"org.projects.clusters.providerSettings.providerName": "GCP"},
                        {"org.projects.clusters.providerSettings.backingProviderName": "GCP"},
                    ]},
                    {"org.projects.clusters.providerSettings.regionName": "CENTRAL_US"},
                ]},
                {"$and": [
                    {"$or": [
                        {"org.projects.clusters.providerSettings.providerName": "AZURE"},
                        {"org.projects.clusters.providerSettings.backingProviderName": "AZURE"},
                    ]},
                    {"org.projects.clusters.providerSettings.regionName": "EUROPE_NORTH"},
                ]},
            ]
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "clusterId": "$org.projects.clusters.id",
            "clusterName": "$org.projects.clusters.name",
            "providerName": "$org.projects.clusters.providerSettings.providerName",
            "backingProviderName": "$org.projects.clusters.providerSettings.backingProviderName",
            "regionName": "$org.projects.clusters.providerSettings.regionName",
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "clusterName": 1,
            "providerName": 1,
            "backingProviderName": 1,
            "regionName": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        if "backingProviderName" in rec:
            providerDetails = rec["backingProviderName"]
        else:
            providerDetails = rec["providerName"]

        nonCompliancesList.append(ClusterNonCompliance(rec["orgId"], rec["orgName"],
                                                       rec["projectId"], rec["projectName"],
                                                       rec["clusterId"], rec["clusterName"],
                                                       "Using banned region for a cloud provder",
                                                       f"{providerDetails}: {rec['regionName']}"))

    return nonCompliancesList


##
# NON-COMPLIANCE CHECK: Check for databases clusters which don't have backup enabled.
##
def checkForNonBackedUpClusters(coll):
    pipeline = [
        {"$sort": {
            "timestamp": -1,
        }},

        {"$limit": 1},

        {"$unwind": {
            "path": "$org.projects",
        }},

        {"$unwind": {
            "path": "$org.projects.clusters",
        }},

        {"$match": {
             "org.projects.clusters.providerBackupEnabled": False,
        }},

        {"$project": {
            "_id": 0,
            "orgId": "$org.id",
            "orgName": "$org.name",
            "projectId": "$org.projects.id",
            "projectName": "$org.projects.name",
            "clusterId": "$org.projects.clusters.id",
            "clusterName": "$org.projects.clusters.name",
            "providerBackupEnabled": "$org.projects.clusters.providerBackupEnabled",
        }},

        {"$sort": {
            "orgName": 1,
            "projectName": 1,
            "clusterName": 1,
            "providerBackupEnabled": 1,
        }},
    ]

    nonCompliancesList = []

    for rec in coll.aggregate(pipeline):
        nonCompliancesList.append(ClusterNonCompliance(rec["orgId"], rec["orgName"],
                                                       rec["projectId"], rec["projectName"],
                                                       rec["clusterId"], rec["clusterName"],
                                                       "Cluster does not have backup enabled",
                                                       "disabled"))

    return nonCompliancesList


# Constants
DO_DB_DATA_COLLECT = False
DEFAULT_MONGODB_URL = "mongodb://localhost:27017"
DEFAULT_DBNAME = "atlas_org_configuration"
DEFAULT_COLLNAME = "config"
BASE_ATLAS_ADMIN_URL = "https://cloud.mongodb.com/api/atlas/v1.0"
FIXED_QUERY_PARAMS = {"itemsPerPage": 500}  # Doesn't cope with multiple pages of 'next' results
INFINITE_RECURSION_LEVEL_THRESHOLD = 1000
RESULTS_JSON_KEY = "results"
LINKS_JSON_KEY = "links"
REL_LINK_JSON_KEY = "rel"
HREF_LINK_JSON_KEY = "href"
ID_JSON_FIELD = "id"
NAME_JSON_FIELD = "name"
PROJECT_RESOURCES_ALIAS = "groups"
PROJECT_RESOURCES_NAME = "projects"
CLUSTERS_RESOURCES_NAME = "clusters"
PROCESS_ARGS_JSON_FIELD = "processArgs"
TIMESTAMP_JSON_KEY = "timestamp"
GROUP_SUB_RESOURCES = [
                       "accessList", "clusters", "maintenanceWindow", "databaseUsers",
                       "alertConfigs", "auditLog", "encryptionAtRest", "globalWrites",
                       "integrations",
                      ]
CHECK_FUNCTION_LIST = [
                        checkForBannedSharedClusters, checkForTooOpenProjectAccessLists,
                        checkForBannedCloudProviders, checkForRiskyTLSVersions,
                        checkForBannedRegionsInCloudProviders, checkForNonBackedUpClusters,
                      ]


##
# Main
##
if __name__ == "__main__":
    main()

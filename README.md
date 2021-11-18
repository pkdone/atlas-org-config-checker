# Atlas Org Config Checker

Demo utility showing how a [MongoDB Atlas](https://www.mongodb.com/atlas) _organisation_'s configuration metadata can be retrieved, stored and then analysed for non-compliances, related to a set of example rules.

The [Admin API](https://docs.atlas.mongodb.com/reference/api-resources/) for MongoDB Atlas does not provide one single resource to call to obtain all the configuration metadata for all the resources contained in an Atlas organisation. Therefore, this utility makes multiple API calls to get configuration data for every resource in the organisation and then combines these into one single representation of the organisation's current configuration. An example of the utility's checks, run against this configuration, is the detection of any 'banned' M0/M2/M5 shared clusters currently deployed in the Atlas organisation.


## Main Process Flow Executed

* Using the Atlas Admin API, assemble a single JSON representation of the full organisation's configuration by polling the Admin API for data from various resources belonging to the organisation (e.g. _org_, _group_ (_project_), _cluster_, _accessList_, etc.).
* Save the retrieved config data as a single document in a MongoDB database collection with an additional timestamp field capturing when the configuration was retrieved.
* Using the aggregation framework, analyse the latest _organisation_ config document, stored in the database, for non-compliances, according to a set of hard-coded example rules 


## Example Implemented Non-Compliance Rule Checks

* Check for banned clusters (typically shared rather than dedicated clusters)
* Check for project access lists that are too open (e.g. allowing 0.0.0.0/0)
* Check for banned cloud providers deployed to (e.g. GCP allowed but AWS & Azure not)
* Check for banned regions in cloud providers deployed too (e.g. AWS in EU-WEST-2)
* Check for risky TLS versions configured (i.e. if TLS version 1.0 or 1.2 used rather than the safer default of 1.2)
* Check for databases deployments configured without backup enabled
* TODO: auditing not enabled
* TODO: enc-at-rest with BYOK not enabled


## Examples Of Non-Compliance Warnings Logged

```
ClusterNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz111', projectName='Paul Demo Project', clusterId='123456', clusterName='RealmCluster', description='Using banned cluster type', badValue='M2')

AccessListNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz222', projectName='Alan Proj Reaper', cidrBlock='0.0.0.0/0', comment='', description='Using subnet mask which is too open', badValue=0)

ClusterNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz333', projectName='eComm', clusterId='23456', clusterName='DemoCluster', description='Using banned cloud provder', badValue='GCP')

ClusterNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz444', projectName='Backend', clusterId='34567', clusterName='TestCluster', description='Using banned minimum TLS version', badValue='TLS1_1')

ClusterNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz555', projectName='Main Data Warehouse', clusterId='45678', clusterName='dev-sandbox', description='Using banned region for a cloud provder', badValue='AZURE: EUROPE_NORTH')

ClusterNonCompliance (orgId='abc123', orgName='SA-NEUR', projectId='xyz666', projectName='Aministrator Reports', clusterId='56789', clusterName='Integration-Test-Cluster', description='Cluster does not have backup enabled', badValue='disabled')
```


## Prerequisites For Running

* You have access to a generated _Organization API Key_ for the organisation you need the utility to inspect
* The API key has an access list defined which allows access from the IP address of the machine that will run this utility
* The API key has the following permissions associated with it: _Organization Read Only_, _Organization Member_, _Organization Billing Admin_
* You have a MongoDB database running and accessible with permissions for this utility to write the retrieved organisation config to a database collection and then query the data back out (this database doesn't have to be running on Atlas)
* Python version 3.7 or greater is installed
* MongoDB's Python Driver (_PyMongo) is installed, e.g.: `pip3 install --user pymongo`
* The Python utility is made executable on the host machine, e.g.: `chmod u+x atlas-org-config-checker.py`


## How To Run

### To View Full Help Options For The Utility

```
./atlas-org-config-checker.py -h
```


### To Execute Atlas Org Checks With Results Persisted To A Database

Note: Replace the values for the `-l`, `-p`, `-o` and `-u` parameters with your API public key, your API private key, the ID of your Atlas organisation to inspect, and the URL of the MongoDB database to write the results to, respectively.

```
./atlas-org-config-checker.py -k "dttwone" -p "8e721-ed32-38d-380-33847" -o "bb73cf83ab233329" -u "mongodb+srv://usr:pwd@myclstr.a12z.mongodb.net/"
```

## Outstanding Issues

* The utility only retrieves the first 500 resources of a specific type (e.g. _AccessList_) for the organisation as it currently doesn't detect an Atlas API response which includes a _next_ link for retrieving the subsequent page of 500 results (if any). This would mean for large Atlas organisations some configuration data may be missed off.


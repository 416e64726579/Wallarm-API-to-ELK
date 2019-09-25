# Wallarm-API-to-ELK

This is PoC for retrieving data from Wallarm Cloud and sending it to the ELK stack.
The purpose of which is to verify that certain concepts of interaction with API are not only possible, but also easy to fulfill for real-world application, therefore it is a prototype that is designed to determine feasibility of such implementations.

## Getting Started

This project requires python3 installed on your OS.

Clone project from the repository
```sh
git clone git@github.com:AndreyPetriv-Wallarm/Wallarm-API-to-ELK.git
```
Or download zip archive and unzip it

![Download zip](https://github.com/AndreyPetriv-Wallarm/Wallarm-API-to-ELK/blob/master/.images/download.png?raw=true)

### Prerequisites

Things you need to install are python3 and the package installer (pip3) for Python, installed by default.

Once installed, download required packages

```sh
username@laptop:~$  pip3 install -r requirements.txt
```

Elasticsearch should be installed and configured listening on *localhost:9200*

### Usage

```python 
python3 request.py
```
or
```sh
./request.py
```
### Options
```sh
--batch - the script will use env variables
```
### Example
```sh
$ ./request.py        
Choose the way to authorize on a cloud
1. Username/Password
2. UUID/Secret
Type 1 or 2
Method to authorize is: 2
API domain (without https://): api.wallarm.com
UUID: ************
Secret: 
Choose date for the fetching data
Date in format dd-mm-YYYY: 25-08-2019
```
What the environment variables it looks for?
- Mandatory
```sh
WALLARM_API
``` 
- Optional

Either
```
WALLARM_USERNAME
WALLARM_PASSWORD
```

OR

```
WALLARM_UUID
WALLARM_SECRET
```

If both sets presented, the script use UUID/SECRET to authenticate in the cloud.

Otherwise, interactive mode is on.

### What does the script do?

1. Login in Wallarm API
2. Make requests to the following endpoints
	* Attack
	* Hit (commented by default)
	* Details of the hit (commented by default)
	* Blacklist 
	* Blacklist history
	* Vulnerability
3. Send JSON formatted data to Elasticsearch (*localhost:9200* by default)
4. Create attack.json, hit.json, details.json, blacklist.json, blacklist_history.json, vulnerabilities.json with the information of requested resources

## Deployment

### Start with
- [Elasticsearch]


[Elasticsearch]: <https://www.elastic.co/products/elasticsearch>

package platform

import org.apache.commons.lang3.StringUtils
import groovy.json.JsonSlurperClassic
import groovy.json.JsonOutput
import groovy.json.JsonBuilder
import java.io.Serializable

def fetchKPConfigDetails(credentialID, secretID, configJSONCredentialsID=null){
    def KPCONFIG_URI = null
    def kpConfigUser = null
    def kpConfigPassword = null
    def kpConfigToken = null
    if (configJSONCredentialsID == null){
        withCredentials([usernamePassword(credentialsId: credentialID, usernameVariable: 'user', passwordVariable: 'password'),
                        string(credentialsId: secretID, variable: 'token'),]) {
            kpConfigUser = user
            kpConfigPassword = password
            kpConfigToken = token
        }
    }else{
        withCredentials([string(credentialsId: configJSONCredentialsID, variable: 'kpconfigJSON')]) {
          def credentialObject = new JsonSlurperClassic().parseText(kpconfigJSON)
          KPCONFIG_URI = credentialObject.get('KPCONFIG_URI')
          kpConfigUser = credentialObject.get('KPCONFIG_USER')
          kpConfigPassword = credentialObject.get('KPCONFIG_PASSWORD')
          kpConfigToken = credentialObject.get('KPCONFIG_ACCESSTOKEN')
          KPCONFIG_URI = StringUtils.removeEnd(KPCONFIG_URI, "/")
          //KPCONFIG_URI = KPCONFIG_URI + '/' + 'kpconfig'
        }
    }

    return [kpConfigUser, kpConfigPassword, kpConfigToken, KPCONFIG_URI]
}

def getResourceMap(project, env, credentialID, secretID, configJSONCredentialsID=null){
    (kpConfigUser, kpConfigPassword, kpConfigToken, kpConfigURL) = fetchKPConfigDetails(credentialID, secretID, configJSONCredentialsID)
    def service = "azservices" 
    def profile = project + '-' + env
    def label = "master"
    def filename = "azservices-" + profile + ".json"
    configURL = getConfigURL(env, service, profile, label, filename, kpConfigURL)
    print(configURL)
    return retrieveConfigData(kpConfigUser, kpConfigPassword, kpConfigToken, configURL)
}

def getServiceMap(azService, resourceMap, global=false){
  if (resourceMap == null)
      throw new Exception("Unable to pull services resource configuration from KP Config Service.  The resourceMap is " + resourceMap)
  
  def serviceResources = null
    
  try{
      if (azService == "Global") {
        serviceResources = resourceMap.get("GLOBAL")
      } else {
        serviceResources = resourceMap.get(azService)
    }
  }catch(error){
      throw new Exception("Failed to get the service map. Please check the service has been onboarded by Platform Team")
  }
  return serviceResources
  
}

def whitelist (ipWhiteListFlag, azfirewallcheck, azfirewallcreate, azService, azdelete, serviceResources, azureservicesflag) {
	print("Creating the firewall commands for azService: " + azService)                   
    whitelistCmd = ""
    key = 'ip_cidr'
    ipWhiteList = serviceResources.get(key)               
    if (ipWhiteList == null || ipWhiteList == '' || ipWhiteList == "omit") {
         return whitelistCmd
    }

    whitelistCmd = '\n(\n' +
                   'set -e\n'

    if (ipWhiteListFlag) {
        //  whitelistCmd = whitelistCmd + 'iplist=`'+ azfirewallcheck +'`\n'        
      if (ipWhiteList != null) {
        whitelistCmd = whitelistCmd + 'rulelList=`' + azfirewallcheck +'`\n'
        ipWhiteList.eachWithIndex {
          subnet_value, i ->  
		  	    cidr = ''       
            if (subnet_value.indexOf('/') == -1)
              cidr = subnet_value + '/24'
            else           
              cidr = subnet_value
   
            def subnetInfo = new org.apache.commons.net.util.SubnetUtils(cidr).getInfo()
            def startip = subnetInfo.getLowAddress()
            def endip = subnetInfo.getHighAddress()

            switch(azService){
              case "az_synapse":
              case "az_mssql":
              case "az_postgresql":
                i = i + 1;
                rule_name = "MS_PEER_ADV_${i}"
                whitelistCmd = whitelistCmd + 'check=`echo $rulelList | grep "' + rule_name + '" | wc -l`\n' + 'if [ $check -eq 0 ]; then\n'
                        whitelistCmd = whitelistCmd + azfirewallcreate + ' -n ' + rule_name + ' --start-ip-address ' + startip + ' --end-ip-address ' + endip + '\n'
                break;
              case "az_redis_cache":
                redis_rule_name = ["KP_On_Premise","KP_VPN_Address_Pool"]
                rule_name = redis_rule_name[i]
                whitelistCmd = whitelistCmd + 'check=`echo $rulelList | grep "' + rule_name + '" | wc -l`\n' + 'if [ $check -eq 0 ]; then\n'
                whitelistCmd = whitelistCmd + azfirewallcreate + ' --rule-name ' + rule_name + ' --start-ip ' + startip + ' --end-ip ' + endip + '\n'
                break;
              case "az_keyvault":
              case "az_storage_blob":
              case "az_storage_adlsg2":
                i = i + 1;
                rule_name = "MS_PEER_ADV_${i}"              
                        whitelistCmd = whitelistCmd + 'check=`echo $rulelList | grep "' + cidr + '" | wc -l`\n' + 'if [ $check -eq 0 ]; then\n'
                        whitelistCmd = whitelistCmd + azfirewallcreate + ' --ip-address ' + cidr + '\n'
                break;
              default:
                println "Service Unidentified"
                whitelistCmd = whitelistCmd + "\n exit 1 \n"
                break;

            }

			             
            whitelistCmd = whitelistCmd + 'else\n' +
                          'echo ' + cidr + ' is already setup in IP whitelist\n' +
                          'fi\n' 
			
        }

        if (azureservicesflag) {
              if (azService == "az_synapse" || azService == "az_mssql") {
                rule_name = "MS_PEER_AZS"
                startip = "0.0.0.0"
                endip = startip
                whitelistCmd = whitelistCmd + 'check=`echo $rulelList | grep "' + rule_name + '" | wc -l`\n' + 'if [ $check -eq 0 ]; then\n'
                whitelistCmd = whitelistCmd + azfirewallcreate + ' -n ' + rule_name + ' --start-ip-address ' + startip + ' --end-ip-address ' + endip + ' \nfi'
              } else {
                  println "Azure services not requested"
              } 
            }
      }
    }

    whitelistCmd = whitelistCmd + '\nsleep 30 \n)\n' +
          'errorCode=$?\n' +
          'if [ $errorCode -ne 0 ]; then\n' +
            'if [ "$serviceExists" == "false" ]; then\n' +
              'echo "We have an error. Deleting the instance."\n' + 
              azdelete + '\n' +
            'else\n'+
              'echo "We have an error. Skipping Delete step as working on an existing service instance."\n' + 
            'fi\n' +
            'exit $errorCode\n' +
          'fi\n'
    return whitelistCmd
}

def addVNET(name, networkRuleCommand, networkRuleCheckCommand,azResourceGrp, parsedJson, serviceResources, azDeleteCommand, ruleNameFlag){
  
  generatedVnetCommand = ''

  networkRules = serviceResources.get('networkRules')
  if (networkRules == null)
    return generatedVnetCommand 

  if (networkRules != null && networkRules.getClass() != java.util.ArrayList)
            throw new Exception("invalid type provided for networkRules. Please contact the Platform team for support")

  def ruleIndex = 0
  for (networkRule in networkRules){
        // Generating full path of subnet
    azNtwResrcGrp = networkRule.get('virtualNetworkResourceGroup')
    vnetName = networkRule.get('virtualNetworkName')
    subnets = networkRule.get('subnets')
    ruleName = networkRule.get('ruleName')
    subscriptionKey = 'azSubscriptionId'
    azSubscriptionId = serviceResources.get(subscriptionKey)
    
    if (azNtwResrcGrp == null || vnetName == null || subnets == null ){
        println("Azure Resource virtual network (VNET): " + azNtwResrcGrp)
        println("Azure Resource virtual network Name (VNET): " + vnetName)
        println("Azure Resource subnet name(VNET): " + subnets)
        println("Skiping the addition of VNET'S (Service Endpoint addition) as one of the above values has not been given")
        throw new Exception("Please provide virtualNetworkResourceGroup, virtualNetworkName, subnets in networkRules")
    }
  
    if (!subnets instanceof ArrayList)
      throw new Exception("Please provide the Vnet - subnets to be added as service endpoints as an array")
    ruleNameIndex = 0
    for(subnetName in subnets){
        networkRuleCreateCommand = null
        subnetID = '/subscriptions/' + azSubscriptionId + "/resourceGroups/" + azNtwResrcGrp + "/providers/Microsoft.Network/virtualNetworks/" + vnetName + "/subnets/" + subnetName
        command = 'echo "adding vnet: '+subnetID+'"' +
        '\n(\n' +
        'set -e\n'
          if (ruleNameFlag){
            ruleNameID = (ruleName != null)? ruleName + '_' + ruleNameIndex:name + '_' + ruleIndex
            networkRuleCreateCommand = networkRuleCommand + " --name " + ruleNameID
            ruleNameIndex = ruleNameIndex + 1
            ruleIndex = ruleIndex + 1
          }else{
            networkRuleCreateCommand = networkRuleCommand
          }
      
          checkCommand = networkRuleCheckCommand + '\'' +subnetID + '\')"'
          command = command + 
          'if $(' + checkCommand +'); then\n' +
          'echo "Network Rule already Exists. Skipping addition of the subnet:'+ subnetID +'"\n' +
          'else\n'+
          'echo "Network Rule does not Exists. Creating a network rule"\n' +
          networkRuleCreateCommand +
          ' -g ' + azResourceGrp + 
          ' --subnet ' + subnetID + '\n'+
          'fi\n'
          command = command + '\n)\n'+
          'errorCode=$?\n' +
          'echo "returnCode for adding vnet command: $errorCode"\n' +
          'if [ "$errorCode" -ne 0 ]; then\n' +
          'echo "Failed to add the VNET. Deleting the instance"\n' +
          'if [ "$serviceExists" == "false" ]; then\n' +
          'echo "We have an error. Deleting the instance."\n' + 
          azDeleteCommand + '\n' +
          'else\n'+
          'echo "We have an error. Skipping Delete step as working on an existing service instance."\n' + 
          'fi\n'+
          'echo "Please contact the administrators"\n' +
          'exit "$errorCode"\n' +
          'else\n'+
          'echo "VNET added successfully."\n' +
          'fi\n'
          generatedVnetCommand = generatedVnetCommand + command
      }
  }
  return generatedVnetCommand
}


def getNetworkRuleIds(serviceResources){
  
  vnetIds = []

  networkRules = serviceResources.get('networkRules')
  if (networkRules == null)
    return vnetIds 

  if (networkRules != null && networkRules.getClass() != java.util.ArrayList)
      throw new Exception("invalid type provided for networkRules. Please contact the Platform team for support")

  for (networkRule in networkRules){
        // Generating full path of subnet
      azNtwResrcGrp = networkRule.get('virtualNetworkResourceGroup')
      vnetName = networkRule.get('virtualNetworkName')
      subnets = networkRule.get('subnets')
      subscriptionKey = 'azSubscriptionId'
      azSubscriptionId = serviceResources.get(subscriptionKey)
      
      if (azNtwResrcGrp == null || vnetName == null || subnets == null ){
        println("Azure Resource virtual network (VNET) Resource Group: " + azNtwResrcGrp)
        println("Azure Resource virtual network Name (VNET): " + vnetName)
        println("Azure Resource subnet name(VNET): " + subnets)
        println("Skiping the addition of VNET'S (Service Endpoint addition) as one of the above values has not been given")
        throw new Exception("Please provide virtualNetworkResourceGroup, virtualNetworkName, subnets in networkRules")
      }
      

      if (!subnets instanceof ArrayList)
        throw new Exception("Please provide the Vnet - subnets to be added as service endpoints as an array")

      for(subnetName in subnets){
        networkRuleCreateCommand = null
        subnetID = '/subscriptions/' + azSubscriptionId + "/resourceGroups/" + azNtwResrcGrp + "/providers/Microsoft.Network/virtualNetworks/" + vnetName + "/subnets/" + subnetName
        vnetIds.add(subnetID)
      }
  }

  return vnetIds;
}

def getSubnetID(resourceGroup, vnet, subnet){
  getIDCommand = '(az network vnet subnet show -g '+ resourceGroup+ ' --vnet-name ' + vnet + ' -n ' + subnet +' --query id --output tsv)'
  return getIDCommand
}

def subnetValidate(subnetID) {
  
  def checkCommand = 'az network vnet subnet show --ids '+ subnetID + ' --query \"contains(id, \'' + subnetID + '\')\"'
  checkCommand = 'if $(' + checkCommand +'); then\n'  +
                 'echo "subnet:'+ subnetID +' Exists"\n' +
                 'else\n'+
                 'echo "Subnet ID does not exists"\n' + 'exit 1' + '\n' +
                 'fi\n'
  return checkCommand
}

def getUserAssignedIdentity(resourceGroup, name){
  getIDCommand = '(az identity show -g ' + resourceGroup + ' -n ' + name +' --query id --output tsv)' 
  return getIDCommand
}

def getDomainID(subscriptionID, resourceGroup, name){
    getIDCommand = '/subscriptions/'+subscriptionID+'/resourceGroups/' +
                    resourceGroup + '/providers/Microsoft.AAD/domainServices/' + 
                    name
    return getIDCommand
}

def getKPConfigBaseURL(env){
    def kpconfigNonProdURL = 'https://kpconfig-np.bmxp.appl.kp.org/kpconfig'
    def kpconfigProdURL = 'https://kpconfig.bmxp.appl.kp.org/kpconfig'
    println "Environment: " + env
    if (env == 'prod' || env == 'psup') {
        return kpconfigProdURL 
    }else{
        return kpconfigNonProdURL
    }
}

def getPlatformConfigCreds(env){
  if (env == 'prod' || env == 'psup') {
      return ['platform-config-prod-read-only-creds', 'platform-config-prod-read-only-token'] 
  }else{
      return ['platform-config-read-only-creds', 'platform-config-read-only-token']
      
  }
}
 
def getConfigURL(env, service, profile, label, filename=null, KPCONFIG_URI=null){ 
 baseurl = (KPCONFIG_URI != null)? KPCONFIG_URI:getKPConfigBaseURL(env)
 kpconfigURL = baseurl + '/' + service + '/' + profile + '/' + label
 if(filename != null && filename != ''){
  kpconfigURL = kpconfigURL + '/' + filename
 }
 return kpconfigURL
}

def getPlatformConfigURL(env, org) {
  filename = 'azservices-' + org + '-' + env + '.json'
  baseurl = getKPConfigBaseURL(env) + 'azservice-' + org + '/' + env + '/master' + '/' + filename
  return baseurl
}


def retrieveConfigData (String configUser, String configPass, String configToken, String configURL) {
  try {
		authString = configUser + ':' + configPass
    base64String = authString.getBytes().encodeBase64().toString()
	  configValue = getJsonFromConfigService(configURL, configToken, base64String)
    configMap = parseJson(configValue)
		//  println "## Done Parsing JSON  Platform Map " + platformMap + "\n"
 	  return configMap
   } catch (err) {
    println '################## Failed TO GET VALUES FROM KPCONFIG FOR PLATFORM DEFUALT VALUES. ERROR = ' + err
    err.printStackTrace()
    throw err
  }
}

def parseJson(json) {
	rootKeyMap = null
	serviceKeyMap = null
	returnKeyMap = null
  try {
		if (json == null)
		  throw new Exception("The retreived configuration from KP config service is not configured in JSON format.")
		rootKeyMap = [:]
		json.each {
			jsonAttr, jsonValue ->
			  if (jsonAttr != "services") {
					if (jsonAttr != '_comment')
				    rootKeyMap.put(jsonAttr, jsonValue)
				} else {
					serviceKeyMap = jsonValue
				}	
		}
		returnKeyMap = [:]
		returnKeyMap.put("GLOBAL", rootKeyMap)
		if (serviceKeyMap != null) {
		  serviceKeyMap.each {
			  serviceAttr, serviceValue ->
					serviceValue = parseServiceKeyMap(serviceValue, rootKeyMap, null);
				  returnKeyMap.put(serviceAttr, serviceValue);   
		  }

		}
  } catch (err) {
    println '################## UNABLE TO PARSE PLATFORM DEFAULT VALUES. ERROR = ' + err
    err.printStackTrace()
    throw err
  }
  return returnKeyMap
}

def getJsonFromConfigService (url, configToken, base64String) {
  def connection = null
	connection = new URL(url)
			.openConnection() as HttpURLConnection
	connection.setRequestProperty( 'access_token',  configToken.replaceAll("[\\\t|\\\n|\\\r]",""))
	connection.setRequestProperty( 'authorization', 'Basic ' + base64String.replaceAll("[\\\t|\\\n|\\\r]","") )
	connection.setRequestProperty( 'cache', 'no-cache' )
	configValue = connection.inputStream.text
  def responseCode = connection.getResponseCode();
  println("KpConfig Endpoint: " + url)
  println("KpConfig Rest call Response Code: " + responseCode)
  def jsonResponse = new JsonSlurperClassic().parseText(configValue)
  connection = null
  if(responseCode.equals(200) && !jsonResponse.keySet().contains('ErrorCode')) {
      return jsonResponse
  } else {
    println(jsonResponse.get('ErrorCode'))
    throw new Exception(configValue)
  }
}

def parseServiceKeyMap (srvMap, rootMap, envMap) {
	retEnvMap = [:]
	if (srvMap == null || rootMap == null)
	  return retMap
	
	rootMap.each {
		rootK, rootV ->
			envMap.each { 
				envKey, envValue ->
					if (envValue != 'omit') {
						retEnvMap.put(envKey, envValue)
					}
			}	
			srvMap.each {
				
				srvK, srvV ->
				
				if (retEnvMap.get(srvK) == null && srvV != 'omit') {
					if ((envMap != null && envMap.get(rootK) != 'omit') || (envMap == null)){
						retEnvMap.put(srvK, srvV)
					}
					
				}
			}
			if (retEnvMap.get(rootK) == null && rootV != 'omit'){
			  if ((envMap != null && envMap.get(rootK) != 'omit' && srvMap != null && srvMap.get(rootK) != 'omit')  || (envMap== null && srvMap != null && srvMap.get(rootK) != 'omit')){
				retEnvMap.put(rootK, rootV)
			  }
			}
	}
	return retEnvMap;
}

// Add Roles functions
def addRole(serviceResources, path, azDeleteCommand){
    command = ''

    serviePrinciplesMap = serviceResources.get('servicePrincipals')
    if (serviePrinciplesMap != null){
        command = command + addRoleCommand(serviePrinciplesMap, true, serviceResources, path, azDeleteCommand)
    }

    managedIdentitiesMap = serviceResources.get('managedIdentities')
    if (managedIdentitiesMap != null){
        command = command + addRoleCommand(managedIdentitiesMap, false, serviceResources, path, azDeleteCommand)
    }

    return command;
    

}

def addRoleCommand(userMap, sflag, serviceResources, path, azDeleteCommand){
    roleCommand = ''
    for(userRole in userMap){
      getidCommand = null
      userName = userRole.get('name')
      if (sflag){
          getidCommand = '(az ad sp list --display-name ' + userName + 
                         ' --query [].objectId --output tsv)'
      }else{
          getidCommand = '(az identity show -g ' + serviceResources.get('resource_group') +
                          ' --name ' + userName +
                          ' --query principalId --output tsv)'
      }
      singleroleCommand = 
                  '\n(\n' +
                   'set -e\n' +
                      'az role assignment create ' +
                      ' --role ' + userRole.get('roleName') +
                      ' --assignee-object-id $' + getidCommand + 
                      ' --scope '+ path +
                  ')\n' + 
                  getValidateCommand(userName, azDeleteCommand)
      
      roleCommand = roleCommand + singleroleCommand
      

    }
    
    return roleCommand
}

def getValidateCommand(name, azDeleteCommand){
    validateCommand = 'errorCode=$?\n' +
                    'echo "returnCode for add user role: $errorCode"\n' +
                    'if [ $errorCode -ne 0 ]; then\n' +
                    'echo "Faled to add role for:"'+name+'\n' +
                    azDeleteCommand + '\n' +
                    'exit $errorCode\n' +
                    'else\n'+
                    'echo "role successfully added for user: "'+name+'\n' +
                    'fi\n'

    return validateCommand
}


def diagnosticeSettingsCommand(scopeType, scopeValue, serviceResources, metrics){
  def conditions = new platform.azure.conditions()
  cmd = 'az monitor diagnostic-settings create -n ' + name +
        ' --workspace ' + workspaceName +
        ' --resource ' + conditions.getScopePath(scopeType, scopeValue, serviceResources) + 
        ' --metrics ' + metrics

  reurn cmd;
}


def getUserConfigData(env, kpConfigInfo){
  configJSONCredentialsID = kpConfigInfo.get('configJSONCredentialsID')
  kpConfigCredentialID = kpConfigInfo.get('credentialID')
  tokenSecretID = kpConfigInfo.get('secretID')
  (kpConfigUser, kpConfigPassword, kpConfigToken, kpConfigURL) = fetchKPConfigDetails(kpConfigCredentialID, tokenSecretID, configJSONCredentialsID)
  
  profile = (kpConfigInfo.get("profile") != null)?kpConfigInfo.get("profile"):kpConfigInfo.get("configProfile")
  label = (kpConfigInfo.get("label") != null)?kpConfigInfo.get("label"):kpConfigInfo.get("configLabel")
  serviceName = (kpConfigInfo.get("serviceName") != null)?kpConfigInfo.get("serviceName"):kpConfigInfo.get("configName")
  
  
  fileName = kpConfigInfo.get("fileName")
  if (serviceName == null || label == null || profile == null)
      throw new Exception("Please provide configProfile/profile, configLabel/label, configName/serviceName in the kpconfig-info")
  
  
  configURL = getConfigURL(env, serviceName, profile, label, fileName, kpConfigURL)
  authString = kpConfigUser + ':' + kpConfigPassword
  base64String = authString.getBytes().encodeBase64().toString()
  userConfigData = getJsonFromConfigService(configURL, kpConfigToken, base64String)
  return getPropertySources(userConfigData)
  
}

def getPropertySources(userConfigData){
  if (userConfigData.get("propertySources") != null){
      configData = [:]
      propertySources = userConfigData.get("propertySources")
      for (propertySource in propertySources){
          if (propertySource.get('source') != null){
              source = propertySource.get('source')
              if (configData.keySet().size() != 0){
                for (key in source.keySet()){
                    configData[key] = source[key]  
                }    
              }else{
                  configData = source
              }
          }
      }
      return configData
  }

  return  userConfigData

}

def getKPConfigValue(paramValue, userConfigData, platformConfig=null){
    def configValue = null
    def kpconfigKey = ""
    if (paramValue.startsWith("#CONFIG_PARAM_")){
      kpconfigKey = paramValue.split("#CONFIG_PARAM_")[1]
      if (userConfigData.get(kpconfigKey) == null)
        throw new Exception(kpconfigKey+" does not exist in the configuration fetched from kpconfig. Please create all necessary configuration and try again")
    
      configValue = userConfigData.get(kpconfigKey)
    }else{
      kpconfigKey = paramValue.split("#PLATFORM_CONFIG_PARAM_")[1]
      if (platformConfig == null || platformConfig.get(kpconfigKey) == null)
        throw new Exception(kpconfigKey+" does not exist in the configuration fetched from platform kpconfig. Please connect platform team to create all necessary configuration and try again")
      configValue = platformConfig.get(kpconfigKey)
    }
    
    return configValue
}

def getParamValue(paramValue, userConfigData, serviceResources=null, platformConfig=null){
    returnValue = paramValue
    if (!(paramValue instanceof String)) {
          returnValue = paramValue
    }else if (paramValue.startsWith("#CONFIG_PARAM_") || paramValue.startsWith("#PLATFORM_CONFIG_PARAM_")){
        returnValue = getKPConfigValue(paramValue, userConfigData, platformConfig)
    }else if (paramValue.startsWith("#PARAM_")){
        paramConfigValue = paramValue.split("#PARAM_")[1]
        if (!paramConfigValue.contains("="))
            throw new Exception(paramValue+" starts with #PARAM_. Please assign an applicable param type like STORAGE_ACCOUNT and its value after = sign either a plain text or using #CONFIG_PARAM_")
        configValueConfig = paramConfigValue.split("=")
        configType = configValueConfig[0]
        configValue = configValueConfig[1]
        scopeValue = null
        if (configValue.startsWith("#CONFIG_PARAM_")){
            scopeValue = getKPConfigValue(configValue, userConfigData)
        }else{
            scopeValue = configValue
        }

        def conditions = new platform.azure.conditions()
        returnValue = conditions.getScopePath(configType, scopeValue, serviceResources)
    }else{
        returnValue = paramValue
    }      
    return returnValue
}

def validateRequestorIsPlatform(serviceType){
  def conditions = new platform.azure.conditions()
  def platformControlledServices = conditions.getPlatformControlledServices()
  def  repoName = sh(script: 'basename -s .git `git config --get remote.origin.url  | grep . && echo $1 || echo "Adhoc"`', returnStdout: true).trim()
  def platformRepos = conditions.getPlatformRepos()
  if (platformControlledServices.contains(serviceType)){
    println("Validating the requestor. This service is only allowed by plaform team")
    if (!platformRepos.contains(repoName))
      throw new Exception("Only Platform Team can deploy service: " + serviceType + ". Please contact platform team for this deployment.")
    return true  
  } else if(platformRepos.contains(repoName)) {
      return true
  } else {
      return false
  }
}

def getTags(parsedJson){
  tags = ""
  tagsObject = parsedJson.get("tags")
  if (tagsObject != null){
    if (tagsObject.getClass() == java.util.HashMap){
      for (tag in tagsObject){
        tags = tags + tag.key + "=" + tag.value + "\t"
      }
    }else{
      throw new Exception("Invalid input. Please provide the tags to be created as a jsonobject")
    }

  }

  return tags
}

from mythic_c2_container.MythicRPC import *
import sys
import json
from pathlib import Path
import netifaces
import os

# request is a dictionary: {"action": func_name, "message": "the input",  "task_id": task id num}
# must return an RPCResponse() object and set .status to an instance of RPCStatus and response to str of message
async def test(request):
    response = RPCResponse()
    response.status = RPCStatus.Success
    response.response = "hello"
    resp = await MythicRPC().execute("create_event_message", message="Test message", warning=False)
    return response


# The opsec function is called when a payload is created as a check to see if the parameters supplied are good
# The input for "request" is a dictionary of:
# {
#   "action": "opsec",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def opsec(request):
    return {"status": "success", "message": "No OPSEC Check Performed\n"}


# The config_check function is called when a payload is created as a check to see if the parameters supplied
#   to the agent match up with what's in the C2 profile
# The input for "request" is a dictionary of:
# {
#   "action": "config_check",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
#
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def config_check(request):
    output = ""
    try:
        with open("../c2_code/config.json") as f:
            config = json.load(f)
            agent_config = json.loads(request["parameters"]["raw_c2_config"])
            output += f"\n[*] Checking server config for layout structure"
            status = check_server_layout(config)
            if status["status"] == "error":
                return {"status": 'error', "error": output + status["error"]}
            output += status["output"]
            output += f"\n[+] Server config layout structure is good"
            output += f"\n[*] Checking agent config for layout structure"
            status = check_agent_config_layout(agent_config)
            if status["status"] == "error":
                return {"status": "error", "error": output + status["error"]}
            output += status["output"]
            output += f"\n[+] Agent config layout structure is good"
            # now check that server_config can understand an agent_config message
            # first check a GET request
            status = check_config(config,agent_config, "GET")
            if status["status"] == "error":
                return {"status": "error", "error": output + status["error"]}
            output += status["output"]
            status = check_config(config, agent_config, "POST")
            if status["status"] == "error":
                return {"status": "error", "error": output + status["error"]}
            output += status["output"]
            output += "\n[+] Agent and Server Fully Match!"
            return {"status": "success", "message": output}
    except Exception as e:
        return {"status": "error", "error": str(sys.exc_info()[-1].tb_lineno) + str(e)}


# The redirect_rules function is called on demand by an operator to generate redirection rules for a specific payload
# The input for "request" is a dictionary of:
# {
#   "action": "redirect_rules",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def redirect_rules(request):
    return {"status": "error", "error": "Not implemented for dynamichttp yet"}


def check_server_layout(server_config) -> dict:
    output = ""
    if "instances" not in server_config:
        output += f'\n[-] config.json must start with "instances"'
        return {"status": "error", "error": output}
    for inst in server_config["instances"]:
        # loop through all the instances listed to see if the supplied config matches one of them
        for method in ["GET", "POST"]:
            if method not in inst:
                output += f'\n[-] Missing "{method}" element in instance'
                return {"status": "error", "error": output}
            if "ServerBody" not in inst[method]:
                output += f'\n[-] Missing "ServerBody" array in {method}'
                return {"status": "error", "error": output}
            for f in inst[method]["ServerBody"]:
                if "function" not in f:
                    output += f'\n[-] Missing "function" name in {method} ServerBody'
                    return {"status": "error", "error": output}
                if "parameters" not in f:
                    output += f'\n[-] Missing "parameters" array in {method} in ServerBody (can be an empty array indicated by []'
                    return {"status": "error", "error": output}
            if "ServerHeaders" not in inst[method]:
                output += f'\n[-] Missing "ServerHeaders" dictionary'
                return {"status": "error", "error": output}
            if "ServerCookies" not in inst[method]:
                output += f'\n[-] Missing "ServerCookies" dictionary'
                return {"status": "error", "error": output}
            if "AgentMessage" not in inst[method]:
                output += f'\n[-] Missing "AgentMessage" array'
                return {"status": "error", "error": output}
            if len(inst[method]["AgentMessage"]) == 0:
                output += f'\n[*] "AgentMessage" array is empty, so you won\'t be able to do {method} messages'
            for m in inst[method]["AgentMessage"]:
                if "urls" not in m:
                    output += '\n[-] Missing "urls" array indicating urls where the agent will reach out to'
                    return {"status": "error", "error": output}
                if "uri" not in m:
                    output += '\n[-] Missing "uri" indicator of what the URI will be. If not in use, set to empty string'
                    return {"status": "error", "error": output}
                if "urlFunctions" not in m:
                    output += '\n[-] Missing "urlFunctions" array, if you don\'t intent to do any manipulations here, set to empty array []'
                    return {"status": "error", "error": output}
                for f in m["urlFunctions"]:
                    if "name" not in f:
                        output += '\n[-] Missing "name" parameter in urlFunction'
                        return {"status": "error", "error": output}
                    if "value" not in f:
                        output +=  '\n[-] Missing "value" parameter in urlFunction. This is the starting value before transforms are applied'
                        return {"status": "error", "error": output}
                    if "transforms" not in f:
                        output += '\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                        return {"status": "error", "error": output}
                    for t in f["transforms"]:
                        if "function" not in t:
                            output += '\n[-] Missing "function" name in transforms in urlFunctions'
                            return {"status": "error", "error": output}
                        if "parameters" not in t:
                            output += '\n[-] Missing "parameters" array in transforms in urlFunctions (can be an empty array indicated by []'
                            return {"status": "error", "error": output}
                if "AgentHeaders" not in m:
                    output += '\n[-] Missing "AgentHeaders" dictionary, this can be blank if the agent won\'t set any headers (i.e. {}'
                    return {"status": "error", "error": output}
                if "QueryParameters" not in m:
                    output +=  '\n[-] Missing "QueryParameters" array in GET. If no query parameters will be set, leave as empty array []'
                    return {"status": "error", "error": output}
                for f in m["QueryParameters"]:
                    if "name" not in f:
                        output += '\n[-] Missing "name" parameter in QueryParameters'
                        return {"status": "error", "error": output}
                    if "value" not in f:
                        output += '\n[-] Missing "value" parameter in QueryParameters. This is the starting value before transforms are applied'
                        return {"status": "error", "error": output}
                    if "transforms" not in f:
                        output += '\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                        return {"status": "error", "error": output}
                    for t in f["transforms"]:
                        if "function" not in t:
                            output += '\n[-] Missing "function" name in transforms in QueryParameters'
                            return {"status": "error", "error": output}
                        if "parameters" not in t:
                            output += '\n[-] Missing "parameters" array in transforms in QueryParameters (can be an empty array indicated by []'
                            return {"status": "error", "error": output}
                if "Cookies" not in m:
                    output += '\n[-] Missing "Cookies" array in GET. If none will be set, leave as empty array []'
                    return {"status": "error", "error": output}
                for f in m["Cookies"]:
                    if "name" not in f:
                        output += '\n[-] Missing "name" parameter in Cookies'
                        return {"status": "error", "error": output}
                    if "value" not in f:
                        output += '\n[-] Missing "value" parameter in Cookies. This is the starting value before transforms are applied'
                        return {"status": "error", "error": output}
                    if "transforms" not in f:
                        output += '\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                        return {"status": "error", "error": output}
                    for t in f["transforms"]:
                        if "function" not in t:
                            output += '\n[-] Missing "function" name in transforms in Cookies'
                            return {"status": "error", "error": output}
                        if "parameters" not in t:
                            output += '\n[-] Missing "parameters" array in transforms in Cookies (can be an empty array indicated by []'
                            return {"status": "error", "error": output}
                if "Body" not in m:
                    output += '\n[-] Missing "Body" array in GET message. If none will be supplied, set as empty array []'
                    return {"status": "error", "error": output}
        if "no_match" not in inst:
            output += f'\n[-] Missing "no_match" dictionary'
            return {"status": "error", "error": output}
        if "action" not in inst["no_match"]:
            output += f'\n[-] Missing "action" key in "no_match"'
            return {"status": "error", "error": output}
        if inst["no_match"]["action"] not in [
            "redirect",
            "proxy_get",
            "proxy_post",
            "return_file",
        ]:
            output += f"\n[-] no_match action isn't in the approved list"
            return {"status": "error", "error": output}
        if "redirect" not in inst["no_match"]:
            output += f'\n[-] Missing "redirect" option in no_match'
            return {"status": "error", "error": output}
        if "proxy_get" not in inst["no_match"]:
            output += f'\n[-] Missing "proxy_get" option in no_match'
            return {"status": "error", "error": output}
        if "url" not in inst["no_match"]["proxy_get"]:
            output += f'\n[-] Missing "url" in no_match\'s proxy_get dictionary'
            return {"status": "error", "error": output}
        if "status" not in inst["no_match"]["proxy_get"]:
            output += f'\n[-] Missing "status" code for no_match\'s proxy_get dictionary'
            return {"status": "error", "error": output}
        if "proxy_post" not in inst["no_match"]:
            output += f'\n[-] Missing "proxy_post" option in no_match'
            return {"status": "error", "error": output}
        if "url" not in inst["no_match"]["proxy_post"]:
            output += f'\n[-] Missing "url" in no_match\'s proxy_post dictionary'
            return {"status": "error", "error": output}
        if "status" not in inst["no_match"]["proxy_post"]:
            output += f'\n[-] Missing "status" code in no_match\'s proxy_post dictionary'
            return {"status": "error", "error": output}
        if "return_file" not in inst["no_match"]:
            output += f'\n[-] Missing "return_file" in no_match'
            return {"status": "error", "error": output}
        if "name" not in inst["no_match"]["return_file"]:
            output += f'\n[-] Missing "name" for the file to be returned in no_match case'
            return {"status": "error", "error": output}
        if not os.path.exists("../c2_code/" + inst["no_match"]["return_file"]["name"]):
            output += f'\n[-] File specified in "no_match" case for "return_file" can\'t be found'
            return {"status": "error", "error": output}
        if "status" not in inst["no_match"]["return_file"]:
            output += f'\n[-] Misisng "status" return code for no_match\'s return_file'
            return {"status": "error", "error": output}
        if "port" not in inst:
            output += f'\n[-] Missing "port" in instance'
            return {"status": "error", "error": output}
        if "key_path" not in inst:
            output += '\n[-] Missing "key_path" in instance'
            return {"status": "error", "error": output}
        if inst["key_path"] != "" and not os.path.exists("../c2_code/" + inst["key_path"]):
            output += "\n[-] Key_path file can't be found"
            return {"status": "error", "error": output}
        if "cert_path" not in inst:
            output += '\n[-] Missing "cert_path" in instance'
            return {"status": "error", "error": output}
        if inst["cert_path"] != "" and not os.path.exists("../c2_code/" + inst["cert_path"]):
            output += "\n[-] cert_path file can't be found"
            return {"status": "error", "error": output}
        if "debug" not in inst:
            output += f'\n[-] Missing "debug" boolean in instance'
            return {"status": "error", "error": output}
    return {"status": "success", "output": output}


def check_agent_config_layout(inst):
    output = ""
    for method in ["GET", "POST"]:
        if method not in inst:
            output += f'\n[-] Missing "{method}" element in instance'
            return {"status": "error", "error": output}
        if "ServerBody" not in inst[method]:
            output += f'\n[-] Missing "ServerBody" array in {method}'
            return {"status": "error", "error": output}
        for f in inst[method]["ServerBody"]:
            if "function" not in f:
                output += f'\n[-] Missing "function" name in {method} ServerBody'
                return {"status": "error", "error": output}
            if "parameters" not in f:
                output += f'\n[-] Missing "parameters" array in {method} in ServerBody (can be an empty array indicated by []'
                return {"status": "error", "error": output}
        if "ServerHeaders" not in inst[method]:
            output += '\n[-] Missing "ServerHeaders" dictionary'
            return {"status": "error", "error": output}
        if "ServerCookies" not in inst[method]:
            output += '\n[-] Missing "ServerCookies" dictionary'
            return {"status": "error", "error": output}
        if "AgentMessage" not in inst[method]:
            output += '\n[-] Missing "AgentMessage" array'
            return {"status": "error", "error": output}
        if len(inst[method]["AgentMessage"]) == 0:
            output += f'\n[*] "AgentMessage" array is empty, so you won\'t be able to do {method} messages'
        for m in inst[method]["AgentMessage"]:
            if "urls" not in m:
                output += f'\n[-] Missing "urls" array indicating urls where the agent will reach out to'
                return {"status": "error", "error": output}
            if "uri" not in m:
                output += f'\n[-] Missing "uri" indicator of what the URI will be. If not in use, set to empty string'
                return {"status": "error", "error": output}
            if "urlFunctions" not in m:
                output += f'\n[-] Missing "urlFunctions" array, if you don\'t intent to do any manipulations here, set to empty array []'
                return {"status": "error", "error": output}
            for f in m["urlFunctions"]:
                if "name" not in f:
                    output += f'\n[-] Missing "name" parameter in urlFunction'
                    return {"status": "error", "error": output}
                if "value" not in f:
                    output += f'\n[-] Missing "value" parameter in urlFunction. This is the starting value before transforms are applied'
                    return {"status": "error", "error": output}
                if "transforms" not in f:
                    output += f'\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                    return {"status": "error", "error": output}
                for t in f["transforms"]:
                    if "function" not in t:
                        output += f'\n[-] Missing "function" name in transforms in urlFunctions'
                        return {"status": "error", "error": output}
                    if "parameters" not in t:
                        output += f'\n[-] Missing "parameters" array in transforms in urlFunctions (can be an empty array indicated by []'
                        return {"status": "error", "error": output}
            if "AgentHeaders" not in m:
                output += f'\n[-] Missing "AgentHeaders" dictionary, this can be blank if the agent won\'t set any headers'
                return {"status": "error", "error": output}
            if "QueryParameters" not in m:
                output += f'\n[-] Missing "QueryParameters" array in GET. If no query parameters will be set, leave as empty array []'
                return {"status": "error", "error": output}
            for f in m["QueryParameters"]:
                if "name" not in f:
                    output += f'\n[-] Missing "name" parameter in QueryParameters'
                    return {"status": "error", "error": output}
                if "value" not in f:
                    output += '\n[-] Missing "value" parameter in QueryParameters. This is the starting value before transforms are applied'
                    return {"status": "error", "error": output}
                if "transforms" not in f:
                    output += f'\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                    return {"status": "error", "error": output}
                for t in f["transforms"]:
                    if "function" not in t:
                        output += f'\n[-] Missing "function" name in transforms in QueryParameters'
                        return {"status": "error", "error": output}
                    if "parameters" not in t:
                        output += f'\n[-] Missing "parameters" array in transforms in QueryParameters (can be an empty array indicated by []'
                        return {"status": "error", "error": output}
            if "Cookies" not in m:
                output += f'\n[-] Missing "Cookies" array in GET. If none will be set, leave as empty array []'
                return {"status": "error", "error": output}
            for f in m["Cookies"]:
                if "name" not in f:
                    output += f'\n[-] Missing "name" parameter in Cookies'
                    return {"status": "error", "error": output}
                if "value" not in f:
                    output += f'\n[-] Missing "value" parameter in Cookies. This is the starting value before transforms are applied'
                    return {"status": "error", "error": output}
                if "transforms" not in f:
                    output += f'\n[-] Missing "transforms" array. If no transforms needed, set to empty array []'
                    return {"status": "error", "error": output}
                for t in f["transforms"]:
                    if "function" not in t:
                        output += f'\n[-] Missing "function" name in transforms in Cookies'
                        return {"status": "error", "error": output}
                    if "parameters" not in t:
                        output += f'\n[-] Missing "parameters" array in transforms in Cookies (can be an empty array indicated by []'
                        return {"status": "error", "error": output}
            if "Body" not in m:
                output += f'\n[-] Missing "Body" array in GET message. If none will be supplied, set as empty array []'
                return {"status": "error", "error": output}
    if "jitter" not in inst:
        output += '\n[-] Missing "jitter"'
        return {"status": "error", "error": output}
    if "interval" not in inst:
        output += '\n[-] Missing "interval"'
        return {"status": "error", "error": output}
    if "chunk_size" not in inst:
        output += '\n[-] Missing "chunk_size"'
        return {"status": "error", "error": output}
    if "key_exchange" not in inst:
        output += '\n[-] Missing "key_exchange" boolean'
        return {"status": "error", "error": output}
    if "kill_date" not in inst:
        output += '\n[-] Missing "kill_date"'
        return {"status": "error", "error": output}
    return {"status": "success", "output": output}


def check_config(server_config, agent_config, method):
    # get info for agent config
    output = ""
    agent_message = {"location": "", "value": "", "method": method}
    output += f"\n[*] Processing AgentMessages that will leverage HTTP {method} requests"
    for i in range(len(agent_config[method]["AgentMessage"])):
        # we need to find where the "message" parameter exists so we know where the data will be
        g = agent_config[method]["AgentMessage"][i]
        agent_message["urls"] = g["urls"]
        agent_message["uri"] = g["uri"]
        output += f"\n[*] Total variations of AgentMessage for {method}: {len(agent_config[method]['AgentMessage'])}"
        output += "\n[*] Variations are chosen at random for every message"
        output += f"\n[*]\tVariation {i + 1}:"
        output += f"\n   \t\tBase URL endpoints (agent will randomly reach out to these):"
        for u in g["urls"]:
            output += f"\n   \t\t\t{u}"
        output += f"\n   \t\tAll of these URLS have this base URI:"
        output += f"\n   \t\t\t{g['uri']}"
        uriModString = ""
        for p in g["urlFunctions"]:
            if p["name"] != "<message:string>":
                if uriModString == "":
                    uriModString += "\n   \t\t\tWith the following transformations:"
                uriModString += f"\n   \t\t\t\t{p['name']} modified by the following functions:"
                uriModString += f"\n   \t\t\t\t\t" + ",".join([t["function"] for t in p["transforms"]])
        if uriModString != "":
            output += uriModString
        for p in g["QueryParameters"]:
            if p["value"] == "message":
                output += f"\n   \t\tAgent will send message in QueryParameter: {p['name']}"
                agent_message["location"] = "QueryParameters"
                agent_message["value"] = p
        for p in g["Cookies"]:
            if p["value"] == "message":
                output += f"\n   \t\tAgent will send message in Cookie named: {p['name']}"
                agent_message["location"] = "Cookies"
                agent_message["value"] = p
        for p in g["urlFunctions"]:
            if p["name"] == "<message:string>":
                output += f"\n   \t\tAgent will send message in the {method} URI"
                agent_message["location"] = "URI"
                agent_message["value"] = p
        if agent_message["location"] == "":
            # if we haven't set it yet, data must be in the body
            output += f"\n   \t\tAgent will send message in the Body of the request"
            agent_message["location"] = "Body"
            agent_message["value"] = g["Body"]
        output += f"\n   \t\t\tNow checking server config for matching section"
        status = check_match_to_server(server_config, agent_message)
        if status["status"] == "error":
            return {"status": "error", "error": output + status["error"]}
        output += status["output"]
    return {"status": "success", "output": output}


def check_match_to_server(server_config, agent_message):
    output = ""
    server_options = ""

    for inst in server_config["instances"]:
        # only look into AgentMessage details if the urls and uri match
        for g in inst[agent_message["method"]]["AgentMessage"]:
            match = False
            server_options += f"\n   \t\t\tURLS: {g['urls']}"
            server_options += f"\n   \t\t\t\tURI: {g['uri']}"
            if agent_message["uri"] != g["uri"]:
                continue
            if not urls_match(agent_message["urls"], g["urls"]):
                continue
            output += f"\n   \t\t\tFound matching URLs and URI"
            if agent_message["location"] == "Body":
                output += f"\n   \t\tChecking for matching transforms on the message Body"
                match = body_match(g["Body"], agent_message["value"])
                if match["status"] == "error":
                    output += "\n" + match["error"]
                    return {"status": "error", "error": output}
                output += match["output"]
                return {"status": "success", "output": output}
            else:
                output += f"\n   \t\tChecking for matching transforms on the message"
                match = contains_element(
                    agent_message["value"], g[agent_message["location"]]
                )
                if match["status"] == "error":
                    output += match["error"]
                    return {"status": "error", "error": output}
                output += match["output"]
                return {"status": "success", "output": output}
    output += "\n[-]\t Failed to find any matching URLs/URIs in the server config.json"
    output += "\n   \t\tServer contains: "
    output += server_options
    return {"status": "error", "error": output}


def transforms_match(arr1, arr2):
    output = ""
    if len(arr1) != len(arr2):
        return {"status": "error", "error": "Length of applied transformations is different."}
    if len(arr1) == 0:
        return {"status": "success", "output": "\n   \t\t\tAgent and Server match with both performing no transforms!"}
    for i in range(len(arr1)):
        output += f"\n   \t\t\tServer: {arr1[i]['function']}, Agent: {arr2[i]['function']}"
        if arr1[i]["function"] != arr2[i]["function"]:
            return {"status": "error", "error": output + "\n   \t\t\t\tMismatched function names"}
        if len(arr1[i]["parameters"]) != len(arr2[i]["parameters"]):
            return {"status": "error", "error": output + "\n   \t\t\t\tMismatched function parameter lengths"}
        for j in range(len(arr1[i]["parameters"])):
            if arr1[i]["parameters"][j] != arr2[i]["parameters"][j]:
                return {"status": "error", "error": output + "\n   \t\t\t\tMismatched parameter values"}
    output += "\n   \t\t\tAgent and Server match!"
    return {"status": "success", "output": output}


def body_match(arr1, arr2):
    output = ""
    if len(arr1) != len(arr2):
        return {"status": "error", "error": "Length of applied transformations is different."}
    for e in range(len(arr1)):
        output += f"\n   \t\t\tServer: {arr1[e]['function']}, Agent: {arr2[e]['function']}"
        if arr1[e]["function"] != arr2[e]["function"]:
            return {"status": "error", "error": output + "\n   \t\t\t\tMismatched function names"}
        if len(arr1[e]["parameters"]) != len(arr2[e]["parameters"]):
            return {"status": "error", "error": output + "\n   \t\t\t\tMismatched function parameter lengths"}
        for p in range(len(arr1[e]["parameters"])):
            if arr1[e]["parameters"][p] != arr2[e]["parameters"][p]:
                return {"status": "error", "error": output + "\n   \t\t\t\tMismatched parameter values"}
    output += "\n   \t\t\tAgent and Server match!"
    return {"status": "success", "output": output}


def contains_element(ele, arr):
    # check  if arr  contains ele
    for i in arr:
        if i["name"] == ele["name"]:
            if i["value"] == ele["value"]:
                status = transforms_match(ele["transforms"], i["transforms"])
                return status
    return {"status": "error", "error": "\n   \t\t\tFailed to find matching agent message location"}


def urls_match(arr1, arr2):
    if len(arr1) != len(arr2):
        return False
    for i in range(len(arr1)):
        if arr1[i] not in arr2:
            return False
    return True
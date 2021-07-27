from mythic_c2_container.C2ProfileBase import *
import json

def readAgentConfig() -> str:
    with open("../c2_code/agent_config.json", "r") as f:
        data = json.load(f)
        return json.dumps(data, indent=4)


class DynamicHTTP(C2Profile):
    name = "dynamichttp"
    description = "Manipulate HTTP(S) requests and responses"
    author = "@its_a_feature_"
    is_p2p = False
    is_server_routed = False
    parameters = [
        C2ProfileParameter(
            name="AESPSK",
            description="Crypto type",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            required=False,
            crypto_type=True
        ),
        C2ProfileParameter(
            name="raw_c2_config", description="Agent JSON Config", default_value=readAgentConfig()
        ),
    ]



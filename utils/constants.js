const createAgentJSon={
    "name": "New Agent",
    "voice": {
        "speed": 0.9,
        "voiceId": "Neha",
        "provider": "vapi"
    },
    "model": {
        "model": "gpt-4.1",
        "messages": [
            {
                "role": "system",
                "content": "prompt"
            }
        ],
        "provider": "openai",
        "maxTokens": 500,
        "temperature": 0.5
    },
    "firstMessage": "",
    "voicemailMessage": "",
    "endCallFunctionEnabled": true,
    "endCallMessage": "",
    "transcriber": {
        "model": "nova-3",
        "language": "en",
        "provider": "deepgram",
        "confidenceThreshold": 0.37
    },
    "serverMessages": [
        "end-of-call-report"
    ],
    "maxDurationSeconds": 2290,
    "metadata": {
        "recordingEnabled": true,
        "callForwardingEnabled": false
    },
    "backgroundSound": "off",
    "firstMessageMode": "assistant-waits-for-user",
    "analysisPlan": {
        "structuredDataPlan": {
            "enabled": true,
            "schema": {
                "type": "object",
                "required": [
                    "query",
                    "budget",
                    "sentiment",
                    "requirements",
                    "buying_intent",
                    "purchase_reason",
                    "call_back_datetime",
                    "call_back_scheduled"
                ],
                "properties": {
                    "query": {
                        "type": "string"
                    },
                    "budget": {
                        "type": "string"
                    },
                    "sentiment": {
                        "type": "string"
                    },
                    "requirements": {
                        "type": "string"
                    },
                    "buying_intent": {
                        "type": "string"
                    },
                    "purchase_reason": {
                        "type": "string"
                    },
                    "call_back_datetime": {
                        "type": "string"
                    },
                    "call_back_scheduled": {
                        "type": "boolean"
                    }
                }
            },
            "messages": [
                {
                    "content": "You are an expert data extractor. Extract structured data from the transcript as per schema.",
                    "role": "system"
                }
            ]
        }
    },
    "voicemailDetection": {
        "provider": "vapi",
        "backoffPlan": {
            "maxRetries": 10,
            "startAtSeconds": 0,
            "frequencySeconds": 2.5
        },
        "beepMaxAwaitSeconds": 0
    },
    "backgroundDenoisingEnabled": true,
    "messagePlan": {
        "idleMessages": [
            "Is there anything else you need help with?",
            "Let me know if there's anything you need."
        ]
    },
};
module.exports = createAgentJSon;
const createAgentJSon = {
  name: "New Agent",
  voice: {
    speed: 0.9,
    voiceId: "Neha",
    provider: "vapi",
  },
  model: {
    model: "gpt-4.1-2025-04-14",
    messages: [
      {
        role: "system",
        content: "",
      },
    ],
    provider: "azure-openai",
    maxTokens: 500,
    temperature: 0.5,
  },
  firstMessage: "",
  voicemailMessage: "",
  endCallFunctionEnabled: true,
  endCallMessage: "",
  transcriber: {
    model: "nova-3",
    language: "en",
    provider: "deepgram",
    confidenceThreshold: 0.37,
  },
  serverMessages: ["end-of-call-report"],
  maxDurationSeconds: 600,
  metadata: {
    recordingEnabled: true,
    callForwardingEnabled: false,
  },
  backgroundSound: "off",
  firstMessageMode: "assistant-waits-for-user",
  analysisPlan: {
    structuredDataPlan: {
      enabled: true,
      schema: {
        type: "object",
        required: [
          "query",
          "budget",
          "sentiment",
          "requirements",
          "buying_intent",
          "purchase_reason",
          "call_back_datetime",
          "call_back_scheduled",
        ],
        properties: {
          query: {
            type: "string",
          },
          budget: {
            type: "string",
          },
          sentiment: {
            type: "string",
          },
          requirements: {
            type: "string",
          },
          buying_intent: {
            type: "string",
          },
          purchase_reason: {
            type: "string",
          },
          call_back_datetime: {
            type: "string",
          },
          call_back_scheduled: {
            type: "boolean",
          },
        },
      },
      messages: [
        {
          content:
            "You are an expert data extractor. Extract structured data from the transcript as per schema.\n\nJson Schema:\n{{schema}}\n\nOnly respond with the JSON.",
          role: "system",
        },
        {
          content:
            "Here is the transcript:\n\n{{transcript}}\n\n. Here is the ended reason of the call:\n\n{{endedReason}}\n\n",
          role: "user",
        },
      ],
    },
  },
  voicemailDetection: {
    provider: "vapi",
    backoffPlan: {
      maxRetries: 10,
      startAtSeconds: 0,
      frequencySeconds: 2.5,
    },
    beepMaxAwaitSeconds: 0,
  },
  backgroundDenoisingEnabled: true,
  messagePlan: {
    idleMessages: [
      "Is there anything else you need help with?",
      "Let me know if there's anything you need.",
    ],
  },
};

const beforePrompt = `[Core Behavior Guidelines]  
* Speak in short, clear, complete sentences.  
* Stop speaking immediately when the user interrupts — do not finish your sentence.  
* Resume only after a brief, natural pause by the user.  
* Never assume or share extra information unless directly asked.  
* Use natural pauses (one-point-two to one-point-eight seconds) between answers and after questions.  
* Answer naturally in full sentences — do not use numbered points or bullet lists.  
* Never say any number in individual digits or numerals. Always express them in words to sound more human, e.g., "five thousand" instead of "five zero zero zero."  
* Strictly do not speak numbers independently. Numbers should always be expressed as a whole number. For example, say "twenty-two" instead of "two two."  

[Tone and Style]  
* Tone: Confident, helpful, professional — not salesy.  
* Style:  
  * Be conversational and engaging.  
  * Avoid listing points.  
  * Avoid long-winded or filler responses.  
  * Leave space for interaction.  
  * Don’t talk over the user.  
`;

const afterPrompt = `[Voicemail Handling]  
If voicemail is detected, immediately end the call without leaving any message. Do not engage with or leave information on voicemail systems. Use the <end_call> function as soon as voicemail detection triggers.  

[Final Guidelines]  
* Do NOT finish a sentence if the user speaks. Stop immediately.  
* Resume only after the user pauses.  
* Stay within this and the "Other projects from Signature Global" scope only.  
* Keep tone clear, calm, and concise.  
* Be transparent, fact-based, and supportive — especially for NRIs.  
`;

module.exports = {
  createAgentJSon,
  beforePrompt,
  afterPrompt,
};

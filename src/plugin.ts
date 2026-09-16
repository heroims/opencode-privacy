import type { Plugin } from "@opencode-ai/plugin";
import { loadConfig } from "./config.js";
import { BrokerClient } from "./broker.js";
import { createPrivacyHooks } from "./adapter.js";
const PrivacyPlugin:Plugin=async input=>{
  const config=await loadConfig(input.directory);
  return createPrivacyHooks(config,config.brokerSocket?new BrokerClient(config.brokerSocket):undefined);
};
export default PrivacyPlugin;

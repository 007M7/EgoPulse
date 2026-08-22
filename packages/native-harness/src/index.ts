import type { HarnessAdapter, HarnessCapability } from "@egopulse/agent-sdk";

export const nativeHarnessFramework = Object.freeze({
  graphPackage: "@langchain/langgraph",
  corePackage: "@langchain/core",
});

export class UnconfiguredNativeHarness implements HarnessAdapter {
  readonly capability: HarnessCapability = {
    name: "native-harness-placeholder",
    version: "0",
    supportsStreaming: false,
  };

  async probe(): Promise<"unavailable"> {
    return "unavailable";
  }
}

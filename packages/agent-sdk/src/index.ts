export type HarnessCapability = Readonly<{
  name: string;
  version: string;
  supportsStreaming: boolean;
}>;

export interface HarnessAdapter {
  readonly capability: HarnessCapability;
  probe(): Promise<"available" | "unavailable">;
}

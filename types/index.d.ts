export type SecretRow = { name: string; ttl?: string }

declare module 'claude-code' {
  interface PluginState {
    segredos: { rows: SecretRow[]; hasKeyctl: boolean }
  }
}

// Only the @dotenvx/primitives functions dede uses. None of them expand `$VAR` or evaluate `$(…)`.
declare module "@dotenvx/primitives" {
  export function encrypt(publicKey: string, value: string): string;
  export function decrypt(privateKey: string, value: string): string;
  export function keypair(privateKey?: string): { publicKey: string; privateKey: string };
  export function keyringSync(options?: { fk?: string | string[]; processEnv?: Record<string, string | undefined> }): Record<string, string>;
  export function scan(source: string): { parsed: Record<string, string[]>; comments: Record<string, (string | null)[]> };
  export function upsert(source: string, key: string, value: string | string[]): string;
}

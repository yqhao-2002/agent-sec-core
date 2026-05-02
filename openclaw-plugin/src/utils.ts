import { execFile } from "node:child_process";

export type CliResult = {
  /** Raw stdout text (may be empty) */
  stdout: string;
  /** Raw stderr text (may be empty) */
  stderr: string;
  /** Process exit code (0 = success) */
  exitCode: number;
};

// ---------------------------------------------------------------------------
// Test-only mock support
// ---------------------------------------------------------------------------
type CliMockFn = (args: string[], opts: { timeout?: number }) => Promise<CliResult>;

let _mockFn: CliMockFn | undefined;

/** Test-only: override callAgentSecCli with a mock function. */
export function _setCliMock(fn: CliMockFn): void {
  _mockFn = fn;
}

/** Test-only: remove mock and restore real CLI execution. */
export function _resetCliMock(): void {
  _mockFn = undefined;
}

/**
 * Execute an agent-sec-cli subcommand and return the raw output.
 * Each capability is responsible for parsing stdout on its own.
 */
export async function callAgentSecCli(
  args: string[],
  opts: { timeout?: number } = {},
): Promise<CliResult> {

  // If a mock is active, delegate to it instead of spawning a real process.
  if (_mockFn) {
    return _mockFn(args, opts);
  }

  const timeout = opts.timeout ?? 5000;

  return new Promise((resolve, reject) => {
    execFile(
      "agent-sec-cli",
      args,
      { timeout, maxBuffer: 1024 * 1024 },
      (error, stdout, stderr) => {
        // Fail-open: Never reject. Always resolve with error status.
        // Capabilities check exitCode !== 0 to handle CLI failures gracefully.
        
        // Timeout: execFile sets error.killed = true
        if (error && error.killed) {
          resolve({
            stdout: "",
            stderr: `agent-sec-cli timed out after ${timeout}ms`,
            exitCode: 124, // Standard timeout exit code
          });
          return;
        }
        
        // Return raw output — let each capability decide what to do
        resolve({
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          exitCode: typeof error?.code === "number" ? error.code : (error ? 1 : 0),
        });
      },
    );
  });
}

import type { Reporter, ScanResult } from '../core/types.js';
import { printFinding, printSummary } from '../cli/ui.js';

export class ConsoleReporter implements Reporter {
  name = 'console';

  async generate(result: ScanResult): Promise<void> {
    // Output is handled by the scan command directly
    // This reporter is a no-op when called from the engine
    // since the CLI handles console printing for better UX control
  }
}

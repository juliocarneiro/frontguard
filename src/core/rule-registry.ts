import type { RuleDefinition, RuleLevel } from './types.js';

class RuleRegistry {
  private rules = new Map<string, RuleDefinition>();
  private overrides = new Map<string, RuleLevel>();

  register(rule: RuleDefinition): void {
    this.rules.set(rule.id, rule);
  }

  registerMany(rules: RuleDefinition[]): void {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  get(id: string): RuleDefinition | undefined {
    return this.rules.get(id);
  }

  getAll(): RuleDefinition[] {
    return Array.from(this.rules.values());
  }

  setOverrides(overrides: Record<string, RuleLevel>): void {
    this.overrides.clear();
    for (const [id, level] of Object.entries(overrides)) {
      this.overrides.set(id, level);
    }
  }

  getLevel(id: string): RuleLevel {
    if (this.overrides.has(id)) {
      return this.overrides.get(id)!;
    }
    return 'error';
  }

  isEnabled(id: string): boolean {
    return this.getLevel(id) !== 'off';
  }

  getByCategory(category: string): RuleDefinition[] {
    return this.getAll().filter(r => r.category === category);
  }

  clear(): void {
    this.rules.clear();
    this.overrides.clear();
  }
}

export const ruleRegistry = new RuleRegistry();

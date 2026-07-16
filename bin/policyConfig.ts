import { readFileSync } from 'node:fs';
import { Policy, type PolicyRule } from '../src/core/policy';
import type { Provider } from '../src/core/providers';

const TOP_LEVEL_FIELDS = new Set(['defaultDeny', 'rules']);
const RULE_FIELDS = new Set(['defaultAllow', 'allowChannels', 'denyChannels']);

export interface LoadedPolicy {
  policy: Policy;
  defaultDeny: boolean;
  ruleCount: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseJson(raw: string, label: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    // Never reflect raw config: an operator may have pasted a credential into the wrong variable.
    throw new Error(`${label}: invalid JSON`);
  }
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function parsePolicy(
  raw: string,
  label: 'VOUCHR_POLICY' | 'VOUCHR_POLICY_FILE',
  providers: readonly Pick<Provider, 'id'>[],
): LoadedPolicy {
  const document = parseJson(raw, label);
  if (!isObject(document)) throw new Error(`${label}: expected a JSON policy object`);
  if (Object.keys(document).some((field) => !TOP_LEVEL_FIELDS.has(field))) {
    throw new Error(`${label}: unknown top-level field`);
  }

  const defaultDeny = Object.hasOwn(document, 'defaultDeny') ? document.defaultDeny : false;
  if (typeof defaultDeny !== 'boolean') {
    throw new Error(`${label}: defaultDeny must be a boolean`);
  }

  const configuredRules = Object.hasOwn(document, 'rules') ? document.rules : {};
  if (!isObject(configuredRules)) throw new Error(`${label}: rules must be a JSON object`);

  const providerIds = new Set(providers.map(({ id }) => id));
  const rules: Record<string, PolicyRule> = {};
  for (const [providerId, configuredRule] of Object.entries(configuredRules)) {
    if (!providerIds.has(providerId)) {
      // Do not reflect the unknown key: externally supplied object keys may contain credentials.
      throw new Error(`${label}: rule references an unknown configured provider`);
    }
    if (!isObject(configuredRule)) {
      throw new Error(`${label}: each rule must be a JSON object`);
    }
    if (Object.keys(configuredRule).some((field) => !RULE_FIELDS.has(field))) {
      throw new Error(`${label}: unknown per-rule field`);
    }
    if (!Object.hasOwn(configuredRule, 'defaultAllow') || typeof configuredRule.defaultAllow !== 'boolean') {
      throw new Error(`${label}: each rule requires boolean defaultAllow`);
    }
    if (configuredRule.allowChannels !== undefined && !stringArray(configuredRule.allowChannels)) {
      throw new Error(`${label}: allowChannels must be an array of channel strings`);
    }
    if (configuredRule.denyChannels !== undefined && !stringArray(configuredRule.denyChannels)) {
      throw new Error(`${label}: denyChannels must be an array of channel strings`);
    }

    rules[providerId] = {
      defaultAllow: configuredRule.defaultAllow,
      ...(configuredRule.allowChannels === undefined ? {} : { allowChannels: configuredRule.allowChannels }),
      ...(configuredRule.denyChannels === undefined ? {} : { denyChannels: configuredRule.denyChannels }),
    };
  }

  return {
    policy: new Policy(rules, { defaultDeny }),
    defaultDeny,
    ruleCount: Object.keys(rules).length,
  };
}

/**
 * Load the packaged broker's static provider x channel policy. The inline and file forms are
 * deliberately mutually exclusive: unlike provider arrays, a policy has one defaultDeny value and
 * overlapping rule keys have no unambiguous merge order.
 */
export function loadPolicy(
  providers: readonly Pick<Provider, 'id'>[],
  env: NodeJS.ProcessEnv = process.env,
): LoadedPolicy | undefined {
  const hasInline = env.VOUCHR_POLICY !== undefined;
  const hasFile = env.VOUCHR_POLICY_FILE !== undefined;
  if (hasInline && hasFile) {
    throw new Error('VOUCHR_POLICY and VOUCHR_POLICY_FILE cannot both be set');
  }
  if (!hasInline && !hasFile) return undefined;

  if (hasInline) return parsePolicy(env.VOUCHR_POLICY!, 'VOUCHR_POLICY', providers);

  let raw: string;
  try {
    raw = readFileSync(env.VOUCHR_POLICY_FILE!, 'utf8');
  } catch {
    // The configured path may itself contain secret material, so never include it in the error.
    throw new Error('VOUCHR_POLICY_FILE: cannot read the configured policy file');
  }
  return parsePolicy(raw, 'VOUCHR_POLICY_FILE', providers);
}

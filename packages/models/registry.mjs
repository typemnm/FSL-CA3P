import config from '../../agent/src/deepseek-config.js';

const definitions = Object.freeze([
  { id: 'rule-baseline', name: '규칙 기반 · 대학 실습 IDOR', provider: 'local', mode: 'local-lab-rule' },
  { id: 'deepseek-flash', name: 'DeepSeek Flash', provider: 'deepseek', mode: 'local-lab-general' },
  { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', provider: 'deepseek', mode: 'local-lab-general' },
]);

export function listModels(options = {}) {
  return definitions.map(model => {
    if (model.provider === 'local') return { ...model, available: true,
      supportedModes: ['local-lab-rule'],
      capabilities: ['structured-action', 'deterministic-reflection'], modelRole: 'rule-baseline' };
    try {
      config.resolveDeepSeekOptions({ ...options, env: { ...(options.env ?? process.env), DEEPSEEK_MODEL: model.id } });
      return { ...model, available: true, supportedModes: ['local-lab-general', 'external-general'],
        capabilities: ['json', 'cancel', 'bounded-curl', 'general-evidence-planner'], modelRole: 'constrained-planner' };
    } catch {
      return { ...model, available: false, reason: 'agent/.env의 DeepSeek API 설정이 필요합니다.',
        supportedModes: ['local-lab-general', 'external-general'],
        capabilities: ['json', 'cancel', 'bounded-curl', 'general-evidence-planner'], modelRole: 'constrained-planner' };
    }
  });
}

export const modelDefinitions = definitions;

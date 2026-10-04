'use strict';

const { classify } = require('./normalizer');
const { ConditionEvaluator } = require('./condition-evaluator');
const { isPlainObject, isSubset } = require('./utils');
const { validateRuleset } = require('./ruleset-loader');

class GuardrailEvaluator {
  constructor(ruleset) {
    this.ruleset = validateRuleset(ruleset);
    this.conditions = new ConditionEvaluator();
  }

  evaluate(input) {
    try {
      this.validateInput(input);
      const classification = classify(this.ruleset, input);
      const profile = this.ruleset.profiles[input.trustedContext.testProfile];
      if (!profile) throw new Error(`Unknown testProfile: ${input.trustedContext.testProfile}`);
      this.validateProfileContext(input.trustedContext, profile, input.stage);

      const context = {
        ...input,
        action: input.action,
        trustedContext: input.trustedContext,
        classifications: [...classification.labels],
        matchedClassifiers: classification.matchedClassifiers,
        endpointCatalog: this.ruleset.endpointCatalog,
        profile,
        budget: input.trustedContext.budget,
      };

      for (const rule of this.ruleset.hardDenyRules) {
        if (this.conditions.evaluate(rule.when, context)) return this.deny(rule.id, rule.reason, context);
      }

      if (profile.stageRules) {
        const rule = profile.stageRules.find(item => item.stage === input.stage);
        if (!rule) return this.deny('PROFILE-STAGE-NOT-ALLOWED', '현재 프로필에서 허용되지 않은 단계', context);
        if (rule.exactAction && !isSubset(rule.exactAction, input.action)) {
          return this.deny('PROFILE-ACTION-MISMATCH', '요청이 단계별 허용 행동과 일치하지 않음', context);
        }
        if (rule.constraints && !rule.constraints.every(item => this.conditions.evaluate(item, context))) {
          return this.deny('PROFILE-CONSTRAINT-FAILED', '프로필의 canary 또는 단계 제약을 충족하지 않음', context);
        }
        if (rule.decision !== 'ALLOW') return this.deny('PROFILE-NOT-ALLOW', '프로필 규칙이 실행을 허용하지 않음', context);
        return this.allow(`PROFILE.${input.trustedContext.testProfile}.${input.stage}`, context);
      }

      if (profile.allowedOperation) {
        if (!isSubset(profile.allowedOperation, input.action)) {
          return this.deny('PROFILE-ACTION-MISMATCH', '브라우저 퍼저 행동이 허용 계약과 일치하지 않음', context);
        }
        if (!(profile.constraints || []).every(item => this.conditions.evaluate(item, context))) {
          return this.deny('PROFILE-CONSTRAINT-FAILED', '오프라인 퍼저 격리 조건을 충족하지 않음', context);
        }
        if (profile.decision === 'ALLOW') return this.allow(`PROFILE.${input.trustedContext.testProfile}`, context);
      }
      return this.deny('DEFAULT-DENY', '일치하는 허용 규칙이 없음', context);
    } catch (error) {
      return {
        decision: 'DENY',
        ruleId: 'EVALUATOR-ERROR',
        reason: error.message,
        runId: input?.trustedContext?.runId ?? null,
        stage: input?.stage ?? null,
        normalizedTarget: null,
        matchedClassifiers: [],
        budgetSnapshot: input?.trustedContext?.budget ?? null,
      };
    }
  }

  validateInput(input) {
    if (!isPlainObject(input)) throw new TypeError('Guardrail input must be an object');
    for (const field of this.ruleset.inputContract.required) {
      if (input[field] === undefined) throw new Error(`Missing required input field: ${field}`);
    }
    const allowedInputFields = new Set(this.ruleset.inputContract.required);
    const inputExtras = Object.keys(input).filter(key => !allowedInputFields.has(key));
    if (inputExtras.length) throw new Error(`Unsupported top-level input fields: ${inputExtras.join(', ')}`);
    if (typeof input.stage !== 'string' || !isPlainObject(input.action) || !isPlainObject(input.trustedContext)) {
      throw new TypeError('stage, action, and trustedContext have invalid types');
    }
    const schema = this.ruleset.inputContract.actionSchemas[input.action.operation];
    if (!schema) throw new Error(`Unsupported action operation: ${input.action.operation}`);
    for (const field of schema.required) {
      if (input.action[field] === undefined) throw new Error(`Missing required action field: ${field}`);
    }
    const extras = Object.keys(input.action).filter(key => !schema.allowedFields.includes(key));
    if (extras.length) throw new Error(`Unsupported action fields: ${extras.join(', ')}`);
    for (const field of this.ruleset.inputContract.trustedContext.required) {
      if (input.trustedContext[field] === undefined) throw new Error(`Missing trustedContext field: ${field}`);
    }
  }

  validateProfileContext(trusted, profile, stage) {
    const requirements = profile.trustedContextRequirements || {};
    const stageRule = profile.stageRules?.find(rule => rule.stage === stage);
    const stageUsesBoundCanary = JSON.stringify(stageRule || {}).includes('trustedContext.boundCanary');
    if (requirements.boundCanaryRequired && stageUsesBoundCanary) {
      if (!isPlainObject(trusted.boundCanary)) {
        throw new Error('This stage requires a trusted boundCanary');
      }
      for (const field of requirements.boundCanaryFields || []) {
        if (trusted.boundCanary[field] === undefined || trusted.boundCanary[field] === null) {
          throw new Error(`Missing trusted boundCanary field: ${field}`);
        }
      }
    }
    if (requirements.currentUserId && trusted.currentUser?.id !== requirements.currentUserId) {
      throw new Error('Trusted current user does not match the profile');
    }
    if (requirements.fixtureOwnerId
      && (trusted.fixtureOwner?.id ?? trusted.boundCanary?.ownerId) !== requirements.fixtureOwnerId) {
      throw new Error('Trusted fixture owner does not match the profile');
    }
    if (requirements.externalRequests
      && trusted.networkPolicy?.externalRequests !== requirements.externalRequests) {
      throw new Error('Network policy does not match the profile');
    }
    if (requirements.fuzzerMode
      && trusted.fuzzerEnvironment?.mode !== requirements.fuzzerMode) {
      throw new Error('Fuzzer mode does not match the profile');
    }
    if (requirements.virtualOrigin
      && trusted.fuzzerEnvironment?.virtualOrigin !== requirements.virtualOrigin) {
      throw new Error('Fuzzer virtual origin does not match the profile');
    }
    if (requirements.realServerTested !== undefined
      && trusted.fuzzerEnvironment?.realServerTested !== requirements.realServerTested) {
      throw new Error('Fuzzer real-server flag does not match the profile');
    }
  }

  target(context) {
    return {
      origin: context.trustedContext.targetOrigin,
      method: context.action.method ?? null,
      path: context.action.path ?? null,
    };
  }

  allow(ruleId, context) {
    return {
      decision: 'ALLOW', ruleId,
      reason: '모든 hard-deny, 프로필, canary 및 예산 조건을 충족함',
      runId: context.trustedContext.runId,
      stage: context.stage,
      normalizedTarget: this.target(context),
      matchedClassifiers: context.matchedClassifiers,
      budgetSnapshot: { ...context.trustedContext.budget },
    };
  }

  deny(ruleId, reason, context) {
    return {
      decision: 'DENY', ruleId, reason,
      runId: context.trustedContext.runId,
      stage: context.stage,
      normalizedTarget: this.target(context),
      matchedClassifiers: context.matchedClassifiers,
      budgetSnapshot: { ...context.trustedContext.budget },
    };
  }
}

module.exports = { GuardrailEvaluator };

'use strict';

class RuleReasoningEngine {
  plan({ candidates, expectedTarget }) {
    if (!Array.isArray(candidates) || candidates.length !== 1) {
      return {
        state: 'stop',
        decisionSummary: '정확히 하나의 검증 가능한 후보를 찾지 못해 실행하지 않음',
        action: null,
      };
    }

    const candidate = candidates[0];
    const candidateResourceId = String(candidate?.resource?.id ?? '');
    const candidateOwnerId = String(candidate?.resource?.ownerId ?? '');
    const candidateAttackerId = String(candidate?.attackerId ?? '');
    const expectedResourceId = String(expectedTarget?.resourceId ?? '');
    const expectedOwnerId = String(expectedTarget?.ownerId ?? '');
    const expectedAttackerId = String(expectedTarget?.attackerId ?? '');
    const template = candidate?.actionTemplate;
    const matchesObservedCanary = candidateResourceId === expectedResourceId
      && candidateOwnerId === expectedOwnerId
      && candidateAttackerId === expectedAttackerId;
    const hasExactActionTemplate = template?.method === 'DELETE'
      && template?.pathTemplate === '/api/posts/{resourceId}';
    const isCrossUser = expectedAttackerId.length > 0
      && expectedOwnerId.length > 0
      && expectedAttackerId !== expectedOwnerId;

    if (!matchesObservedCanary || !hasExactActionTemplate || !isCrossUser) {
      return {
        state: 'stop',
        decisionSummary: '외부 후보가 관찰된 canary 또는 허용된 행동 템플릿과 일치하지 않아 실행하지 않음',
        action: null,
      };
    }
    const path = template.pathTemplate.replace('{resourceId}', expectedResourceId);

    return {
      state: 'act',
      decisionSummary: '공격자와 소유자가 다르고 출처가 있는 권한 검사 후보의 전제조건을 만족함',
      hypothesis: '서버가 인증 세션 대신 authorId 쿼리 값을 신뢰하면 교차 사용자 삭제가 허용된다.',
      action: {
        operation: 'http_request',
        session: 'attacker',
        method: 'DELETE',
        path,
        query: { authorId: expectedOwnerId },
      },
      target: {
        resourceId: expectedTarget.resourceId,
        ownerId: expectedOwnerId,
        attackerId: expectedAttackerId,
      },
      knowledge: {
        id: candidate.knowledgeId,
        cwe: candidate.cwe,
        severity: candidate.severity,
        severityBasis: candidate.severityBasis,
        provenance: candidate.provenance,
      },
      expectedEvidence: candidate.successCriteria,
    };
  }

  reflect({ runId, target, before, actionResult, after, evidenceRefs, knowledge }) {
    const differentUsers = target.attackerId !== target.ownerId;
    const existedBefore = before.exists === true;
    const deleteAccepted = actionResult.status >= 200
      && actionResult.status < 300
      && String(actionResult.deletedId) === String(target.resourceId);
    const absentAfter = after.exists === false;
    const confirmed = differentUsers && existedBefore && deleteAccepted && absentAfter;

    return {
      state: 'stop',
      decisionSummary: confirmed
        ? '검증 조건이 모두 충족되어 finding을 확정함'
        : '증거가 불충분하여 finding을 확정하지 않음',
      finding: {
        findingId: `finding-${runId}-cross-user-delete`,
        title: '교차 사용자 게시글 삭제 권한 우회',
        cwe: knowledge.cwe,
        severity: knowledge.severity,
        severityBasis: knowledge.severityBasis,
        confidence: confirmed ? 'high' : 'low',
        status: confirmed ? 'confirmed' : 'not_confirmed',
        actorId: target.attackerId,
        ownerId: target.ownerId,
        resourceId: target.resourceId,
        evidenceRefs,
        checks: { differentUsers, existedBefore, deleteAccepted, absentAfter },
        summary: confirmed
          ? '공격자 세션의 삭제 행동과 사후 부재 증거가 교차 사용자 삭제를 확인했다.'
          : '필수 증거 조건 중 하나 이상이 충족되지 않아 취약점을 확정하지 않았다.',
        limitations: '외부 모듈이 반환한 구조화 증거를 바탕으로 한 단일 반복 판정이다.',
        remediation: '삭제 권한은 요청 파라미터가 아니라 검증된 세션 사용자와 리소스 소유자를 서버에서 비교해야 한다.',
      },
    };
  }
}

module.exports = { RuleReasoningEngine };

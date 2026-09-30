'use strict';

const { parseEnvelope, replyTo } = require('../protocol');

class RuleReasoner {
  async handle(raw) {
    const request = parseEnvelope(raw, 'rule_reasoner');
    if (request.payload.operation === 'plan') return this.plan(request);
    if (request.payload.operation === 'reflect') return this.reflect(request);
    throw new Error('Unsupported reasoner operation');
  }

  plan(request) {
    const candidates = request.payload.candidates;
    if (!Array.isArray(candidates) || candidates.length !== 1) {
      return JSON.stringify(replyTo(request, 'rule_reasoner', 'reasoner.decision', {
        state: 'stop',
        decisionSummary: '정확히 하나의 검증 가능한 후보를 찾지 못해 실행하지 않음',
        action: null,
      }));
    }

    const candidate = candidates[0];
    if (candidate.attackerId === candidate.resource.ownerId) {
      throw new Error('Cross-user precondition was not met');
    }
    const path = candidate.actionTemplate.pathTemplate.replace('{resourceId}', String(candidate.resource.id));
    const ownerId = String(candidate.resource.ownerId);

    return JSON.stringify(replyTo(request, 'rule_reasoner', 'reasoner.decision', {
      state: 'act',
      decisionSummary: '공격자와 소유자가 다르고, 출처가 확인된 로컬 권한 검사 playbook의 전제조건을 만족함',
      hypothesis: '서버가 인증 세션 대신 authorId 쿼리 값을 신뢰하면 교차 사용자 삭제가 허용된다.',
      action: {
        operation: 'http_request',
        session: 'attacker',
        method: 'DELETE',
        path,
        query: { authorId: ownerId },
      },
      target: {
        resourceId: candidate.resource.id,
        ownerId,
        attackerId: candidate.attackerId,
      },
      knowledge: {
        id: candidate.knowledgeId,
        cwe: candidate.cwe,
        severity: candidate.severity,
        severityBasis: candidate.severityBasis,
        provenance: candidate.provenance,
      },
      expectedEvidence: candidate.successCriteria,
    }));
  }

  reflect(request) {
    const { target, before, actionResult, after, evidenceRefs, knowledge } = request.payload;
    const differentUsers = target.attackerId !== target.ownerId;
    const existedBefore = before.exists === true;
    const deleteAccepted = actionResult.status >= 200
      && actionResult.status < 300
      && String(actionResult.deletedId) === String(target.resourceId);
    const absentAfter = after.exists === false;
    const confirmed = differentUsers && existedBefore && deleteAccepted && absentAfter;

    const finding = {
      findingId: `finding-${request.runId}-cross-user-delete`,
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
      checks: {
        differentUsers,
        existedBefore,
        deleteAccepted,
        absentAfter,
      },
      summary: confirmed
        ? 'Alice 인증 세션으로 Bob 소유 게시글을 삭제했고 재조회에서 부재를 확인했다.'
        : '필수 증거 조건 중 하나 이상이 충족되지 않아 취약점을 확정하지 않았다.',
      limitations: '격리된 단일 서버·단일 에이전트 실행이며, 동시 변경이 없는 조건에서 삭제 요청과 사후 부재의 인과를 판단했다.',
      remediation: '삭제 권한은 쿼리의 authorId가 아니라 검증된 세션 사용자와 게시글 소유자를 서버에서 비교해야 한다.',
    };

    return JSON.stringify(replyTo(request, 'rule_reasoner', 'reasoner.reflection', {
      state: 'stop',
      decisionSummary: confirmed ? '세 독립 조건이 모두 충족되어 finding을 확정함' : '증거가 불충분하여 finding을 확정하지 않음',
      finding,
    }));
  }
}

module.exports = { RuleReasoner };

'use strict';

const { storedXssCanaryContent } = require('./xss-canary');

const STORED_XSS_PROFILE = 'stored_xss_canary';
const CROSS_USER_DELETE_PROFILE = 'agent_cross_user_delete_canary';
const XSS_MARKER_PATTERN = /^[a-f0-9]{32}$/;

function stopped(summary) {
  return { state: 'stop', decisionSummary: summary, action: null };
}

function sameOrigin(pageUrl, targetOrigin) {
  if (typeof pageUrl !== 'string' || typeof targetOrigin !== 'string') return false;
  try {
    const target = new URL(targetOrigin);
    const page = new URL(pageUrl);
    return targetOrigin === target.origin && page.origin === target.origin;
  } catch {
    return false;
  }
}

class RuleReasoningEngine {
  plan({ candidates, expectedTarget, testProfile }) {
    if (testProfile === STORED_XSS_PROFILE) {
      return this.planStoredXss({ candidates, expectedTarget });
    }
    if (testProfile !== undefined && testProfile !== CROSS_USER_DELETE_PROFILE) {
      return stopped('허용되지 않은 검증 프로필이므로 실행하지 않음');
    }
    if (!Array.isArray(candidates) || candidates.length !== 1) {
      return stopped('정확히 하나의 검증 가능한 후보를 찾지 못해 실행하지 않음');
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
      return stopped('외부 후보가 관찰된 canary 또는 허용된 행동 템플릿과 일치하지 않아 실행하지 않음');
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

  planStoredXss({ candidates, expectedTarget }) {
    if (!Array.isArray(candidates) || candidates.length !== 1) {
      return stopped('정확히 하나의 저장형 XSS 카나리 후보를 찾지 못해 실행하지 않음');
    }
    const candidate = candidates[0];
    const marker = expectedTarget?.marker;
    const title = expectedTarget?.title;
    const content = expectedTarget?.content;
    const attackerId = expectedTarget?.attackerId;
    const template = candidate?.actionTemplate;
    const validMarker = typeof marker === 'string' && XSS_MARKER_PATTERN.test(marker);
    const validTitle = typeof title === 'string' && title.length <= 120
      && title.startsWith('agent-xss-canary-') && title.endsWith(marker || '');
    const validContent = validMarker && content === storedXssCanaryContent(marker);
    const matchesCanary = candidate?.marker === marker
      && candidate?.title === title
      && candidate?.content === content
      && candidate?.attackerId === attackerId;
    const exactPostTemplate = template?.method === 'POST'
      && template?.pathTemplate === '/api/posts'
      && Object.keys(template).sort().join(',') === 'method,pathTemplate';

    if (!validMarker || !validTitle || !validContent || !matchesCanary
      || typeof attackerId !== 'string' || attackerId.length === 0 || !exactPostTemplate) {
      return stopped('저장형 XSS 후보가 신뢰된 카나리 또는 허용된 POST 템플릿과 일치하지 않아 실행하지 않음');
    }

    return {
      state: 'act',
      decisionSummary: '고유 마커를 가진 로컬 게시글 카나리의 전제조건을 만족함',
      hypothesis: '게시글 내용이 HTML로 렌더링되면 무해한 브라우저 콜백이 실행된다.',
      action: {
        operation: 'http_request',
        session: 'attacker',
        method: 'POST',
        path: '/api/posts',
        body: { title, content },
      },
      target: { marker, title, attackerId },
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

  reflect(input) {
    if (input.testProfile === STORED_XSS_PROFILE) return this.reflectStoredXss(input);
    if (input.testProfile !== undefined && input.testProfile !== CROSS_USER_DELETE_PROFILE) {
      return stopped('허용되지 않은 검증 프로필이므로 판정하지 않음');
    }
    const { runId, target, before, actionResult, after, evidenceRefs, knowledge } = input;
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

  reflectStoredXss({ runId, target, targetOrigin, actionResult, after, evidenceRefs, knowledge }) {
    const marker = target?.marker;
    const postId = target?.postId;
    const validPostId = Number.isInteger(postId) && postId > 0;
    const postCreated = actionResult?.status === 201;
    const postIdMatches = validPostId
      && String(actionResult?.postId) === String(postId)
      && String(after?.postId) === String(postId);
    const markerMatches = typeof marker === 'string' && XSS_MARKER_PATTERN.test(marker)
      && after?.marker === marker;
    const pageOnTarget = sameOrigin(after?.pageUrl, targetOrigin);
    const postVisible = after?.postVisible === true;
    const payloadPresent = after?.payloadPresent === true;
    const bindingCalled = after?.bindingCalled === true;
    const executed = after?.executed === true;
    const noObservationErrors = Array.isArray(after?.errors) && after.errors.length === 0;
    const evidencePresent = Array.isArray(evidenceRefs)
      && evidenceRefs.length >= 2
      && evidenceRefs.every(ref => typeof ref === 'string' && ref.length > 0)
      && new Set(evidenceRefs).size === evidenceRefs.length;
    const confirmed = postCreated && postIdMatches && markerMatches && pageOnTarget
      && postVisible && payloadPresent && bindingCalled && executed
      && noObservationErrors && evidencePresent;

    return {
      state: 'stop',
      decisionSummary: confirmed
        ? 'HTTP 생성 결과와 동일 게시글의 브라우저 실행 증거가 일치하여 finding을 확정함'
        : '동일 게시글의 브라우저 실행 증거가 불충분하여 finding을 확정하지 않음',
      finding: {
        findingId: `finding-${runId}-stored-xss-canary`,
        title: '저장형 XSS 브라우저 실행',
        cwe: knowledge?.cwe,
        severity: knowledge?.severity,
        severityBasis: knowledge?.severityBasis,
        confidence: confirmed ? 'high' : 'low',
        status: confirmed ? 'confirmed' : 'not_confirmed',
        actorId: target?.attackerId,
        resourceId: postId,
        marker,
        evidenceRefs,
        checks: {
          postCreated,
          postIdMatches,
          markerMatches,
          pageOnTarget,
          postVisible,
          payloadPresent,
          bindingCalled,
          executed,
          noObservationErrors,
          evidencePresent,
        },
        summary: confirmed
          ? '카나리 게시글이 생성되었고 같은 게시글의 무해한 마커 콜백이 브라우저에서 실행되었다.'
          : '게시글 생성과 브라우저 실행을 같은 카나리에 연결할 필수 증거가 부족하다.',
        limitations: '분리된 로컬 실습 대상의 한 게시글과 한 번의 브라우저 관찰에 대한 판정이다.',
        remediation: '게시글 내용을 HTML로 삽입하지 말고 텍스트로 렌더링하거나 검증된 HTML 정화 정책을 적용해야 한다.',
      },
    };
  }
}

module.exports = { RuleReasoningEngine };

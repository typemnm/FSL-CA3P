"use strict";
(() => {
  const {report, images, review: initialReview} = JSON.parse(document.getElementById("review-data").textContent);
  let reviewState = structuredClone(initialReview), reviewDirty = false;
  const protectedFields = ["case_id", "status", "source", "source_report"];
  const listFields = ["preconditions", "procedure", "remediation", "not_applicable_fields"];
  const reviewMetadataFields = ["not_applicable_fields", "applicability_reason", "route_template"];
  const acknowledgementCodes = ["endpoint_ambiguity", "combined_vulnerability_types", "typographic_quotes", "image_text_not_processed", "unreviewed_image_transcript", "unreviewed_local_ocr"];
  const labels = {case_id:"사례 ID",target_id:"대상 ID",title:"제목",vulnerability_type:"취약점 종류",reported_on:"발견·점검일",vulnerability_url:"취약 URL",severity:"심각도",description:"설명",remediation:"해결 방안",prior_evidence:"증거 위치",endpoint:"엔드포인트",method:"HTTP 메서드",parameter:"입력 변수",parameter_location:"입력 위치",preconditions:"사전 조건",procedure:"재현 절차",payload:"대표 payload",success_condition:"성공 판정 조건",source_report:"원본 경로",status:"초안 상태",patch_status:"패치 상태",source:"출처"};
  const representations = {literal:"본문·명시적 입력",url_encoded:"URL 인코딩",url_query:"URL 쿼리",image_transcription:"시각 전사 · 미검토",image_ocr:"로컬 OCR · 미검토"};
  Object.assign(labels, {not_applicable_fields:"미적용 입력 필드", applicability_reason:"미적용 근거", route_template:"검토된 경로 템플릿"});
  const methods = {direct:"원문 항목",derived:"파생 값",normalized:"형식 변환",review_candidate:"검토할 관련 문단"};
  let index = 0, tab = "fields";
  const $ = id => document.getElementById(id);
  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  }
  function badge(text, type) { return node("span", text, "badge " + type); }
  function valueText(value) {
    if (value === null || value === undefined || (Array.isArray(value) && !value.length)) return "미확인";
    return Array.isArray(value) ? value.map((v, i) => `${i + 1}. ${v}`).join("\n") : String(value);
  }
  function endpointTitle(f, i) {
    if (f.candidate.endpoint) return f.candidate.endpoint.split("/").filter(Boolean).pop() || "/";
    return `취약점 ${i + 1} · 경로 확인 필요`;
  }
  function navigate(nextTab, nextIndex = index) {
    index = nextIndex; tab = nextTab;
    history.replaceState(null, "", `#finding=${index}&tab=${tab}`);
    render();
    window.scrollTo({top:0, behavior:"instant"});
  }
  function reference(ref) {
    const button = node("button", ref, "ref");
    button.type = "button";
    button.addEventListener("click", () => {
      navigate("raw");
      const target = document.getElementById("raw-" + ref);
      if (target) {
        const card = target.closest(".source-card") || target;
        card.classList.add("highlight"); card.scrollIntoView({behavior:"smooth", block:"center"});
      }
    });
    return button;
  }
  function findingList() {
    const query = $("search").value.trim().toLocaleLowerCase();
    $("findings").replaceChildren();
    report.findings.forEach((f, i) => {
      const haystack = JSON.stringify(f.candidate).toLocaleLowerCase();
      if (query && !haystack.includes(query)) return;
      const button = node("button", undefined, "finding-option");
      button.type = "button"; button.setAttribute("aria-current", String(i === index));
      button.append(node("strong", endpointTitle(f, i)));
      button.append(node("small", `${f.candidate.vulnerability_type || "종류 미확인"} · ${f.candidate.severity || "심각도 미확인"}`));
      button.append(node("small", `누락 ${f.missing_fields.length} · 미확정 ${f.unresolved_fields.length}`));
      button.addEventListener("click", () => navigate(tab, i));
      $("findings").append(button);
    });
    if (!$("findings").children.length) $("findings").append(node("p", "검색 결과가 없습니다.", "side-description"));
  }
  function notice(text, warning = false) { return node("div", text, "notice" + (warning ? " warning" : "")); }
  function fieldView(f) {
    const fragment = document.createDocumentFragment();
    fragment.append(notice("누락 = 확인된 근거 없음 · 미확정 = 후보 근거가 있어 검토 필요. 사전 조건의 빈 배열은 ‘조건 없음’의 확인을 뜻하지 않습니다."));
    const wrap = node("div", undefined, "table-wrap"), table = node("table");
    const head = node("thead"), header = node("tr");
    ["FSL-CA3P 필드", "추출 후보", "분류·사유", "원문 근거"].forEach(t => header.append(node("th", t)));
    head.append(header); table.append(head);
    const body = node("tbody");
    Object.entries(f.candidate).forEach(([key, value]) => {
      const row = node("tr"), name = node("td", undefined, "field-name");
      name.append(node("strong", labels[key] || key), node("code", key)); row.append(name);
      const val = node("td", undefined, "field-value"); val.append(node("pre", valueText(value), valueText(value) === "미확인" ? "empty" : "")); row.append(val);
      const state = node("td"), evidence = f.field_evidence[key] || [];
      const missing = f.missing_fields.includes(key), unresolved = f.unresolved_fields.includes(key);
      const issue = f.review_issues.find(i => i.field === key && i.code === (missing ? "missing_field" : "unresolved_field"));
      let status = missing ? "누락" : unresolved ? "미확정" : evidence.length ? "추출 후보" : "관리·기본값";
      if (missing && ["case_id", "target_id"].includes(key)) status = "관리 정보 미지정";
      state.append(badge(status, missing ? "missing" : unresolved ? "unresolved" : evidence.length ? "extracted" : "default"));
      if (issue) state.append(node("div", issue.message, "reason"));
      row.append(state);
      const source = node("td", undefined, "field-evidence");
      evidence.forEach(e => {
        source.append(badge(methods[e.method] || e.method, "default"), reference(e.source_ref));
        source.append(node("div", valueText(e.value), "evidence-text"));
      });
      if (key === "payload" && f.payload_variants.length) {
        const compare = node("button", `후보 ${f.payload_variants.length}개 비교`, "button");
        compare.addEventListener("click", () => navigate("payloads")); source.append(compare);
        [...new Set(f.payload_variants.map(v => v.source_ref))].forEach(ref => source.append(reference(ref)));
      } else if (!evidence.length) source.append(node("span", missing ? "연결된 원문 근거 없음" : "—", "empty"));
      row.append(source); body.append(row);
    });
    table.append(body); wrap.append(table); fragment.append(wrap);
    const issues = node("details", undefined, "issue-box");
    issues.append(node("summary", `검토 항목 ${f.review_issues.length}개`));
    const list = node("ul");
    f.review_issues.forEach(i => {
      const item = node("li", i.message); item.append(node("div", `${i.field || "보고서"} · ${i.code}`, "reason"));
      i.source_refs.forEach(ref => item.append(reference(ref))); list.append(item);
    });
    issues.append(list); fragment.append(issues); return fragment;
  }
  function payloadView(f) {
    const fragment = document.createDocumentFragment();
    fragment.append(notice("원문 표기를 그대로 보존합니다. 일반 따옴표와 곡선 따옴표, URL 인코딩, 캡처 전사는 서로 구분합니다. 디코딩 값은 비교용이며 대표 payload를 자동 선택하지 않습니다.", true));
    if (!f.payload_variants.length) { fragment.append(node("div", "탐지된 payload 후보가 없습니다. 원문에 남은 내용을 확인하세요.", "empty-panel")); return fragment; }
    const wrap = node("div", undefined, "table-wrap"), table = node("table"), head = node("thead"), header = node("tr");
    ["표기·출처", "보존한 원문 값", "퍼센트 디코딩 비교값"].forEach(t => header.append(node("th", t)));
    head.append(header); table.append(head); const body = node("tbody");
    f.payload_variants.forEach(v => {
      const row = node("tr"), source = node("td"), raw = node("td"), decoded = node("td");
      source.append(badge(representations[v.representation] || v.representation, v.representation === "image_transcription" ? "unresolved" : "default"), reference(v.source_ref));
      raw.append(node("pre", v.value, "payload-value"));
      if (/[“”‘’]/.test(v.value)) raw.append(node("div", "곡선 따옴표 포함 · 자동 치환하지 않음", "payload-note"));
      decoded.append(node("pre", v.percent_decoded_value === null ? "별도 디코딩 값 없음" : v.percent_decoded_value, "payload-value"));
      row.append(source, raw, decoded); body.append(row);
    });
    table.append(body); wrap.append(table); fragment.append(wrap);
    fragment.append(node("p", `대표 payload: ${f.candidate.payload === null ? "미확정" : f.candidate.payload}`, "reason"));
    return fragment;
  }
  function sourceCard(ref, text, heading) {
    const card = node("article", undefined, "source-card"); card.id = "raw-" + ref;
    if (heading) card.append(node("h3", heading));
    card.append(node("div", ref, "eyebrow"), node("pre", text || "(빈 셀)")); return card;
  }
  function rawView(f) {
    const fragment = document.createDocumentFragment();
    fragment.append(notice("표의 셀 텍스트와 캡처를 보여줍니다. 원래 페이지 배치와 서식을 복원한 화면은 아닙니다. " + (report.document.local_ocr ? "로컬 OCR 결과는 미검토 후보이며 캡처와 대조해야 합니다." : "캡처 문자는 OCR로 읽지 않았습니다.")));
    const table = report.document.tables.find(t => t.source_ref === f.source_ref);
    if (table) {
      if (table.preceding_paragraph) {
        const p = table.preceding_paragraph; fragment.append(sourceCard(p.source_ref, p.text, "표 앞의 제목·심각도"));
      }
      table.cells.forEach(cell => {
        const card = sourceCard(cell.source_ref, cell.text, `${cell.row}행 ${cell.column}열`);
        cell.paragraphs.forEach(p => {const anchor = node("span"); anchor.id = "raw-" + p.source_ref; card.append(anchor);});
        fragment.append(card);
      });
    }
    f.image_refs.forEach(id => {
      const meta = report.document.images.find(i => i.image_id === id);
      const figure = node("figure", undefined, "image-card"); figure.id = "raw-image:" + id;
      figure.append(node("h3", `캡처 · ${id}`));
      if (images[id]) {const img = node("img"); img.src = images[id]; img.alt = `보고서 원본 캡처 ${id}`; figure.append(img);}
      else figure.append(node("p", "이 화면에 이미지가 포함되지 않았습니다. 원본 HWPX를 지정해 검토 화면을 다시 생성하세요.", "reason"));
      figure.append(node("figcaption", `${meta?.archive_part || id} · 문자 처리: ${meta?.text_extraction || "미확인"}`));
      const transcript = report.image_transcripts.find(t => t.image_id === id);
      if (transcript) {
        const card = sourceCard("image-transcript:" + id, transcript.text, "별도 시각 전사 · 미검토");
        card.append(node("p", transcript.transcribed_by, "reason")); figure.append(card);
      }
      const ocr = report.document.local_ocr?.bundle?.images.find(item => item.image_id === id);
      if (ocr) {
        figure.append(node("p", `로컬 OCR: ${ocr.status} · 신뢰도 점수 없음 · 원본과 대조 필요`, "reason"));
        (ocr.recognition?.lines || []).forEach((line, i) => {
          figure.append(sourceCard(`image-ocr:${id}#line${i}`, line.text, `OCR ${i + 1}행 · 미검토`));
        });
      }
      fragment.append(figure);
    });
    return fragment;
  }
  function render() {
    findingList(); const f = report.findings[index]; $("panel").replaceChildren();
    if (!f) {$("finding-title").textContent = "취약점 초안이 없습니다."; $("panel").append(node("div", "인식하지 못한 표는 JSON의 document에 보존되어 있습니다.", "empty-panel")); return;}
    $("finding-source").textContent = f.source_ref;
    $("finding-title").textContent = f.candidate.endpoint || endpointTitle(f, index);
    $("finding-url").textContent = f.candidate.vulnerability_url || "영향 URL이 미확정입니다. 원문에 기록된 URL들을 대조하세요.";
    $("finding-badges").replaceChildren(badge(f.candidate.severity || "심각도 미확인", f.candidate.severity || "default"), badge("검토 필요", "unresolved"));
    document.querySelectorAll("[data-tab]").forEach(button => {const selected = button.dataset.tab === tab; button.setAttribute("aria-selected", String(selected)); button.tabIndex = selected ? 0 : -1;});
    $("panel").setAttribute("aria-labelledby", "tab-" + tab);
    if (tab === "fields") $("panel").append(fieldView(f));
    if (tab === "payloads") $("panel").append(payloadView(f));
    if (tab === "raw") $("panel").append(rawView(f));
    if (tab === "json") $("panel").append(notice("현재 선택한 취약점의 JSON입니다. 상단 버튼에서 문서 전체 JSON을 내려받을 수 있습니다."), node("pre", JSON.stringify(f, null, 2), "json-view"));
    if (tab === "review") $("panel").append(reviewView(f));
  }
  function downloadJSON(value, filename) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + "\n"], {type:"application/json"}));
    const link = node("a"); link.href = url; link.download = filename;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function reviewItem(f) {
    let item = reviewState.items.find(value => value.draft_id === f.draft_id);
    if (!item) {
      item = {draft_id:f.draft_id, decision:"pending", reason:"", resolutions:{}, payload_variant_index:null, acknowledged_issue_codes:[]};
      reviewState.items.push(item);
    }
    return item;
  }
  function inputField(label, value, update, options = {}) {
    const wrap = node("label", undefined, "review-field"); wrap.append(node("span", label));
    const input = node(options.multiline ? "textarea" : "input");
    if (!options.multiline) input.type = options.type || "text";
    else input.rows = options.rows || 3;
    input.value = value; if (options.placeholder) input.placeholder = options.placeholder;
    input.addEventListener("input", () => {update(input.value); reviewDirty = true;});
    wrap.append(input); return wrap;
  }
  function selectField(label, choices, value, update) {
    const wrap = node("label", undefined, "review-field"), select = node("select");
    wrap.append(node("span", label));
    choices.forEach(([key, text]) => {const option = node("option", text); option.value = key; select.append(option);});
    select.value = value;
    select.addEventListener("change", () => {update(select.value); reviewDirty = true;});
    wrap.append(select); return wrap;
  }
  function reviewView(f) {
    const fragment = document.createDocumentFragment(), item = reviewItem(f);
    fragment.append(notice("검토 기록만 편집합니다. 원문·추출 JSON은 그대로 유지되며 DB에 저장하지 않습니다. 내려받은 검토 JSON을 명령에 연결하면 Python에서 누락·자료 해시·필드 형식을 다시 검증합니다."));
    fragment.append(notice("탭을 이동해도 입력은 유지됩니다. 새로고침하거나 창을 닫기 전 검토 JSON을 내려받으세요. 빈 값을 ‘없음’으로 바꾸거나 payload를 자동으로 선택하지 않습니다.", true));
    const actions = node("div", undefined, "review-actions"), feedback = node("p", "이 화면의 선택만으로 등록 준비 완료가 되지는 않습니다.", "reason");
    feedback.setAttribute("role", "status");
    const save = node("button", "검토 JSON 내려받기", "button"); save.type = "button";
    save.addEventListener("click", () => {
      downloadJSON(reviewState, "report.review.json"); reviewDirty = false;
      feedback.textContent = "검토 JSON을 내려받았습니다. manifest의 review 경로에 연결하고 automate를 다시 실행하세요. DB 저장 전 검증 결과를 확인할 수 있습니다.";
    });
    const load = node("label", undefined, "review-field"); load.append(node("span", "이전 검토 JSON 불러오기"));
    const file = node("input"); file.type = "file"; file.accept = ".json,application/json";
    file.addEventListener("change", async () => {
      try {
        const selected = file.files[0]; if (!selected) return;
        if (selected.size > 32000000) throw new Error("검토 JSON이 32 MB를 초과합니다.");
        const loaded = JSON.parse((await selected.text()).replace(/^\uFEFF/, ""));
        validateReviewShape(loaded);
        reviewState = loaded; reviewDirty = true; render();
      } catch (error) {feedback.textContent = "불러오기 실패: " + error.message;}
    });
    load.append(file); actions.append(save, load); fragment.append(actions, feedback);
    const meta = node("div", undefined, "issue-box"); meta.append(node("h3", "문서 전체 검토자"));
    meta.append(inputField("검토자", reviewState.reviewer, value => {reviewState.reviewer = value;}));
    meta.append(inputField("검토 시각 · 시간대를 포함한 ISO 형식", reviewState.reviewed_at || "", value => {reviewState.reviewed_at = value || null;}, {placeholder:"YYYY-MM-DDTHH:mm:ss+09:00"}));
    const stamp = node("button", "현재 시각을 검토 시각으로 기록", "button"); stamp.type = "button";
    stamp.addEventListener("click", () => {reviewState.reviewed_at = new Date().toISOString(); reviewDirty = true; render();});
    meta.append(stamp); fragment.append(meta);
    const decision = node("div", undefined, "issue-box"); decision.append(node("h3", "선택한 취약점의 검토 결정"));
    decision.append(selectField("결정", [["pending","검토 중"],["accept","등록 대상으로 검토"],["exclude","근거를 남기고 제외"]], item.decision, value => {item.decision = value;}));
    decision.append(inputField("결정 근거", item.reason, value => {item.reason = value;}, {multiline:true}));
    if (f.payload_variants.length) {
      const choices = [["", "대표 payload를 선택하지 않음"], ...f.payload_variants.map((v, i) => [String(i), `${i + 1}. ${v.value} · ${v.source_ref}`])];
      decision.append(selectField("원문 후보 중 대표 payload 선택", choices, item.payload_variant_index === null ? "" : String(item.payload_variant_index), value => {item.payload_variant_index = value === "" ? null : Number(value);}));
      decision.append(node("p", "직접 payload 값을 보완할 때는 후보 선택을 해제하세요. 두 방식을 동시에 사용하면 서버 검증에서 거부됩니다.", "reason"));
    }
    const issues = f.review_issues.filter(issue => acknowledgementCodes.includes(issue.code));
    const uniqueCodes = [...new Set(issues.map(issue => issue.code))];
    uniqueCodes.forEach(code => {
      const label = node("label", undefined, "review-check"), check = node("input"); check.type = "checkbox";
      check.checked = item.acknowledged_issue_codes.includes(code);
      check.addEventListener("change", () => {
        item.acknowledged_issue_codes = item.acknowledged_issue_codes.filter(value => value !== code);
        if (check.checked) item.acknowledged_issue_codes.push(code); reviewDirty = true;
      });
      label.append(check, node("span", `${code}: ${issues.find(issue => issue.code === code).message} — 원문과 대조해 검토함`)); decision.append(label);
    });
    fragment.append(decision);
    const resolutions = node("div", undefined, "issue-box"); resolutions.append(node("h3", "누락·오류 보완과 근거"));
    resolutions.append(node("p", "확인한 값만 추가하세요. 목록 필드는 한 줄에 한 항목, 원문 근거는 표·문단 식별자 또는 manual:확인 자료 이름으로 기록합니다. 실제 사전 조건을 모르면 비워 두고 검토 중 상태를 유지하세요.", "reason"));
    resolutions.append(node("p", "입력이 없는 유형은 not_applicable_fields에 parameter·payload 중 해당 항목을 기록하고 applicability_reason에 근거를 남깁니다. 경로 템플릿은 확인한 경로의 식별자 자리만 {파라미터명}으로 표시합니다. 입력이 필요한 유형의 누락값을 미적용으로 바꿀 수 없습니다.", "reason"));
    const editable = [...new Set([...Object.keys(f.candidate), ...reviewMetadataFields])].filter(key => !protectedFields.includes(key));
    const available = editable.filter(key => !Object.hasOwn(item.resolutions, key));
    if (available.length) {
      let chosen = available[0];
      resolutions.append(selectField("보완할 필드", available.map(key => [key, `${labels[key] || key} (${key})`]), chosen, value => {chosen = value;}));
      const add = node("button", "필드 보완 추가", "button"); add.type = "button";
      add.addEventListener("click", () => {
        item.resolutions[chosen] = {value:listFields.includes(chosen) ? [] : "", reason:"", source_refs:[]};
        reviewDirty = true; render();
      }); resolutions.append(add);
    }
    Object.entries(item.resolutions).forEach(([key, resolution]) => {
      const card = node("div", undefined, "resolution-card"); card.append(node("h3", `${labels[key] || key} · ${key}`));
      const isList = listFields.includes(key);
      const value = isList ? (Array.isArray(resolution.value) ? resolution.value.join("\n") : "") : (resolution.value ?? "");
      card.append(inputField(isList ? "보완 값 · 한 줄에 한 항목" : "보완 값 · 원문 표기 유지", value, text => {resolution.value = isList ? text.split("\n").filter(line => line !== "") : text;}, {multiline:true}));
      card.append(inputField("보완 근거 설명", resolution.reason, text => {resolution.reason = text;}, {multiline:true, rows:2}));
      card.append(inputField("근거 위치 · 한 줄에 하나", resolution.source_refs.join("\n"), text => {resolution.source_refs = text.split("\n").map(line => line.trim()).filter(Boolean);}, {multiline:true, rows:2, placeholder:"manual:보고서 작성자의 확인 메모"}));
      const remove = node("button", "이 보완 제거", "button"); remove.type = "button";
      remove.addEventListener("click", () => {delete item.resolutions[key]; reviewDirty = true; render();});
      card.append(remove); resolutions.append(card);
    });
    fragment.append(resolutions); return fragment;
  }
  function validateReviewShape(value) {
    if (!value || value.schema_version !== "case-review-1" || value.report_sha256 !== initialReview.report_sha256 || value.draft_sha256 !== initialReview.draft_sha256) throw new Error("현재 원본·추출본과 일치하는 검토 파일이 아닙니다.");
    if (typeof value.reviewer !== "string" || (value.reviewed_at !== null && typeof value.reviewed_at !== "string") || !Array.isArray(value.items)) throw new Error("검토 JSON 형식이 올바르지 않습니다.");
    const ids = new Set();
    value.items.forEach(item => {
      const finding = report.findings.find(f => f.draft_id === item.draft_id);
      if (!finding || ids.has(item.draft_id) || !["pending","accept","exclude"].includes(item.decision) || typeof item.reason !== "string") throw new Error("알 수 없거나 중복된 검토 항목입니다.");
      ids.add(item.draft_id);
      if (!item.resolutions || Array.isArray(item.resolutions) || typeof item.resolutions !== "object" || !Array.isArray(item.acknowledged_issue_codes) || !item.acknowledged_issue_codes.every(code => typeof code === "string")) throw new Error("필드 보완 형식이 올바르지 않습니다.");
      if (item.payload_variant_index !== null && (!Number.isInteger(item.payload_variant_index) || item.payload_variant_index < 0 || item.payload_variant_index >= finding.payload_variants.length)) throw new Error("payload 후보 번호를 확인하세요.");
      Object.entries(item.resolutions).forEach(([key, resolution]) => {
        if ((!Object.hasOwn(finding.candidate, key) && !reviewMetadataFields.includes(key)) || protectedFields.includes(key) || !resolution || typeof resolution.reason !== "string" || !Array.isArray(resolution.source_refs) || !resolution.source_refs.every(ref => typeof ref === "string")) throw new Error("보완 값 또는 근거 형식을 확인하세요.");
        if (listFields.includes(key) ? !Array.isArray(resolution.value) || !resolution.value.every(text => typeof text === "string") : resolution.value !== null && typeof resolution.value !== "string") throw new Error("보완 값 자료형을 확인하세요.");
      });
    });
  }
  $("filename").textContent = report.source.filename || "HWPX 보고서";
  [["취약점 초안", report.findings.length], ["누락 항목", report.findings.reduce((n,f) => n + f.missing_fields.length, 0)], ["미확정 항목", report.findings.reduce((n,f) => n + f.unresolved_fields.length, 0)], ["원본 캡처", report.document.images.length]].forEach(([label, count]) => {const card = node("div", undefined, "stat"); card.append(node("span", label), node("strong", count)); $("stats").append(card);});
  [["원본 경로",report.source.path],["SHA-256",report.source.sha256],["추출기",report.extractor_version],["추출 시각",report.source.extracted_at]].forEach(([key,value]) => $("source-meta").append(node("dt",key), node("dd",value)));
  $("search").addEventListener("input", findingList);
  document.querySelectorAll("[data-tab]").forEach(button => {
    button.addEventListener("click", () => navigate(button.dataset.tab));
    button.addEventListener("keydown", event => {
      const names = ["fields","payloads","raw","json","review"], position = names.indexOf(tab);
      if (["ArrowRight","ArrowLeft","Home","End"].includes(event.key)) {
        event.preventDefault();
        const next = event.key === "Home" ? 0 : event.key === "End" ? names.length - 1 : (position + (event.key === "ArrowRight" ? 1 : names.length - 1)) % names.length;
        navigate(names[next]); $("tab-" + names[next]).focus();
      }
    });
  });
  $("download").addEventListener("click", () => {
    downloadJSON(report, "report.review-draft.json");
  });
  function readRoute() {
    const params = new URLSearchParams(location.hash.slice(1)); const selected = Number(params.get("finding") || 0);
    index = Number.isInteger(selected) && selected >= 0 && selected < report.findings.length ? selected : 0;
    tab = ["fields","payloads","raw","json","review"].includes(params.get("tab")) ? params.get("tab") : "fields"; render();
  }
  window.addEventListener("beforeunload", event => {if (reviewDirty) {event.preventDefault(); event.returnValue = "";}});
  window.addEventListener("hashchange", readRoute); readRoute();
})();

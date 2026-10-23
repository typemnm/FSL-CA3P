package edu.wonchang.portal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class SiteCatalog {
    static final Map<String, Object> SITE = site();
    static final List<Map<String, Object>> NAV = List.of(
            nav("대학안내", "/about", child("대학 소개", "/about"), child("캠퍼스 안내", "/about#campus")),
            nav("입학안내", "/admissions", child("모집 안내", "/admissions"), child("입학 FAQ", "/faq")),
            nav("대학·대학원", "/colleges", child("단과대학", "/colleges"), child("학과 안내", "/colleges#departments")),
            nav("학사안내", "/academics", child("학사제도", "/academics"), child("학사일정", "/schedule")),
            nav("연구·산학", "/research", child("연구 지원", "/research"), child("산학협력", "/research#industry")),
            nav("대학생활", "/campus", child("학생지원", "/campus"), child("공지사항", "/notices"), child("자주 묻는 질문", "/faq")),
            nav("대학홍보", "/news", child("대학 소식", "/news"), child("공지사항", "/notices")),
            nav("시설대여", "/facilities", child("대관 안내", "/facilities"))
    );
    static final List<Map<String, String>> FAQS = List.of(
            faq("입학 원서는 어디에서 접수하나요?", "모집 시기별 원서접수 기간과 제출서류는 입학안내 공지에서 확인할 수 있습니다."),
            faq("수강신청 변경 기간은 언제인가요?", "매 학기 학사일정에 공지되며 학사정보시스템에서 변경할 수 있습니다."),
            faq("장학금 신청 기준은 어떻게 확인하나요?", "대학생활의 학생지원 안내와 공지사항에서 장학금별 신청 기준을 확인하세요."),
            faq("증명서는 어떻게 발급받나요?", "로그인 후 마이페이지에서 관련 민원을 접수하거나 종합서비스센터를 방문하세요."),
            faq("캠퍼스 시설을 대여할 수 있나요?", "시설대여 페이지의 이용 절차를 확인한 후 담당 부서에 문의하세요.")
    );
    static final List<String> NOTICE_TITLES = List.of(
            "2026학년도 2학기 중간고사 및 강의실 안내",
            "지역산업 연계 현장실습 참여학생 모집",
            "2027학년도 수시모집 면접고사 안내",
            "도서관 전자자료 이용 교육 신청",
            "2026학년도 겨울방학 해외연수 참가자 모집",
            "청년 취업 지원 프로그램 접수 안내",
            "장학재단 생활비 지원 대상자 공고",
            "학생회관 시설 개선 공사 안내",
            "학부 연구생 프로그램 설명회",
            "통학버스 노선 조정 안내",
            "대학원 신입생 모집 요강",
            "학사정보시스템 정기 점검 안내"
    );
    static final List<String> NEWS_TITLES = List.of(
            "원창대학교, 지역 기업과 산학협력 협약 체결",
            "해양융합연구소, 지속가능 항만 연구 착수",
            "학생 자율주행팀, 전국 경진대회 우수상",
            "시민 열린강좌에 지역 주민 300명 참여",
            "원창대 박물관, 지역사 특별전 개최",
            "국제교류처, 아시아 대학 교류주간 운영"
    );
    static final List<List<String>> EVENTS = List.of(
            List.of("2학기 중간고사", "2026-10-21", "각 단과대학"),
            List.of("산학협력 채용박람회", "2026-10-29", "체육관"),
            List.of("수시모집 면접고사", "2026-11-14", "대학본부"),
            List.of("동계 계절학기 수강신청", "2026-11-25", "학사정보시스템"),
            List.of("2학기 종강", "2026-12-18", "전 캠퍼스")
    );

    private SiteCatalog() {}

    private static Map<String, Object> site() {
        Map<String, Object> site = new LinkedHashMap<>();
        site.put("id", "wonchang");
        site.put("name", "원창대학교");
        site.put("enName", "WONCHANG UNIVERSITY");
        site.put("tagline", "지역을 품고 세계를 잇다");
        site.put("city", "경상남도 원창시 대학로 77");
        site.put("primary", "#6b2432");
        site.put("secondary", "#b7954c");
        site.put("logoMark", "原");
        site.put("heroTitle", "지역의 가능성이\n세계의 경쟁력이 되다");
        site.put("heroSubtitle", "현장과 연구를 연결하며 함께 성장하는 국립 원창대학교.");
        site.put("founded", "1975");
        site.put("phone", "055-210-1000");
        return Map.copyOf(site);
    }

    private static Map<String, String> child(String label, String href) {
        return Map.of("label", label, "href", href);
    }

    @SafeVarargs
    private static Map<String, Object> nav(String label, String href, Map<String, String>... children) {
        return Map.of("label", label, "href", href, "children", List.of(children));
    }

    private static Map<String, String> faq(String question, String answer) {
        return Map.of("question", question, "answer", answer);
    }

    private static Map<String, String> card(String title, String description, String href) {
        return Map.of("title", title, "description", description, "href", href);
    }

    private static Map<String, Object> section(String heading, String intro, String bodyHtml, List<Map<String, String>> cards) {
        return Map.of("heading", heading, "intro", intro, "bodyHtml", bodyHtml, "cards", cards);
    }

    static Map<String, Object> sectionFor(String key) {
        return switch (key) {
            case "about" -> section("대학안내", "원창대학교는 지식과 실천을 연결하는 배움의 공동체입니다.",
                    "<p>원창대학교는 1975년 설립 이래 교육과 연구, 지역사회 협력을 통해 새로운 가치를 만들어 왔습니다.</p><p>우리 대학은 학생 한 사람의 성장을 중심에 두고 학문 간 경계를 넘는 도전과 열린 협력을 지원합니다.</p>",
                    List.of(card("총장 인사말", "배움의 현장에서 시작되는 변화", "/about#vision"),
                            card("대학 비전", "교육·연구·봉사의 중장기 방향", "/about#vision"),
                            card("오시는 길", "경상남도 원창시 대학로 77", "/about#campus")));
            case "admissions" -> section("입학안내", "새로운 가능성을 향한 첫걸음, 여러분의 도전을 기다립니다.",
                    "<p>수시·정시·편입학·외국인 특별전형의 모집요강과 전형 일정을 확인하세요. 전형별 지원 자격과 제출 서류는 모집 공지를 기준으로 합니다.</p>",
                    List.of(card("수시모집", "학생부 종합·교과 전형 안내", "/notices"),
                            card("정시모집", "모집단위 및 선발 일정", "/notices"),
                            card("편입학", "일반·학사 편입학 안내", "/notices"),
                            card("입학 FAQ", "지원 전에 자주 묻는 질문", "/faq")));
            case "colleges" -> colleges();
            case "academics" -> section("학사안내", "학업의 모든 단계에 필요한 정보를 한곳에서 확인하세요.",
                    "<p>학적, 수업, 졸업, 등록, 장학 및 국제교류에 관한 학사 기준은 학기별 공지와 학사일정을 통해 안내합니다.</p>",
                    List.of(card("학적·수업", "휴학, 복학, 수강신청 안내", "/notices"),
                            card("등록·장학", "등록금과 장학 제도", "/notices"),
                            card("졸업·성적", "성적 평가와 졸업 요건", "/faq"),
                            card("학사일정", "주요 학사 일정 확인", "/schedule")));
            case "research" -> section("연구·산학", "현장의 질문을 연구의 성과로 연결합니다.",
                    "<p>연구지원센터와 산학협력단은 연구 과제의 기획부터 기술 이전, 창업과 지역 협력까지 함께합니다.</p>",
                    List.of(card("연구지원", "연구과제·장비·윤리 지원", "/news"),
                            card("산학협력", "기업과 대학의 공동 성장", "/news"),
                            card("창업지원", "학생과 연구자의 아이디어 사업화", "/news")));
            case "campus" -> section("대학생활", "강의실 밖의 경험이 배움의 폭을 넓힙니다.",
                    "<p>장학, 생활관, 동아리, 상담과 진로 지원 등 학생의 일상을 돕는 서비스를 제공합니다.</p>",
                    List.of(card("학생지원", "장학·상담·진로 서비스", "/mypage"),
                            card("공지사항", "캠퍼스의 최신 안내", "/notices"),
                            card("학사일정", "학기별 주요 일정", "/schedule"),
                            card("입학·학사 FAQ", "자주 묻는 질문과 답변", "/faq"),
                            card("교직원 모바일 업무지원", "학생지원 업무의 처리 현황 확인", "/staff/mobile")));
            case "facilities" -> section("시설대여", "캠퍼스 공간을 교육과 지역사회에 열어 둡니다.",
                    "<p>강당, 세미나실 및 야외공간은 운영 일정과 사용 목적에 따라 대여할 수 있습니다. 대관 신청은 시설 담당 부서에서 검토한 뒤 안내합니다.</p>",
                    List.of(card("대강당", "학술행사와 공연을 위한 공간", "/faq"),
                            card("세미나실", "소규모 회의와 교육 행사", "/faq"),
                            card("신청 절차", "이용 문의 및 승인 절차", "/mypage")));
            default -> throw new IllegalArgumentException("Unknown section: " + key);
        };
    }

    private static Map<String, Object> colleges() {
        List<String> departments = List.of("인문사회대학", "자연과학대학", "공과대학", "해양융합대학", "경상대학", "미래산업대학");
        List<String> majors = List.of("역사문화학과", "사회복지학과", "환경과학과", "기계공학부", "해양시스템공학과", "경제학과");
        List<Map<String, String>> cards = new ArrayList<>();
        for (int i = 0; i < departments.size(); i++) {
            cards.add(card(departments.get(i), majors.get(i) + " 등 학문 분야 안내", "/colleges#departments"));
        }
        return section("대학·대학원", "기초 학문부터 융합 연구까지 폭넓은 배움이 이어집니다.",
                "<p>각 단과대학은 전공 교육과 현장 경험을 연결하고, 대학원은 심화 연구와 전문 역량 개발을 지원합니다.</p>", cards);
    }
}

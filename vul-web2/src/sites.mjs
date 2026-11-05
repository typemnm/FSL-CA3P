export const siteConfigs = {
  daehan: {
    id: 'daehan', name: '대한대학교', enName: 'DAEHAN UNIVERSITY',
    tagline: '배움의 깊이, 세상의 내일', city: '서울특별시 성북구 대학로 118',
    primary: '#102d55', secondary: '#0c817f', logoMark: '大',
    heroTitle: '세상을 향한 배움,\n미래를 여는 대한',
    heroSubtitle: '탐구하는 지성과 실천하는 용기로 더 나은 내일을 만듭니다.',
    founded: '1948', phone: '02-700-1000',
    noticeTitles: [
      '2026학년도 2학기 중간시험 운영 안내',
      '2026학년도 동계 계절학기 수강신청 사전 안내',
      '재학생 전공 탐색 박람회 참가 신청',
      '2027학년도 신입학 전형계획 주요사항',
      '도서관 야간 열람실 운영시간 변경 안내',
      '2026년 2학기 국가장학금 지급 일정',
      '대학원 연구윤리 온라인 교육 안내',
      '교내 무선망 서비스 점검 일정',
      '학생생활관 겨울학기 입사 신청',
      '국제교류 프로그램 설명회 개최',
      '학적 변동 신청 절차 안내',
      '캠퍼스 셔틀버스 임시 운행 안내'
    ],
    newsTitles: [
      '대한대학교, 지역 혁신 융합연구센터 개소',
      '공과대학 연구팀, 차세대 에너지 소재 성과 발표',
      '학생 창업팀, 전국 대학 창업경진대회 수상',
      '인문학연구소, 시민과 함께하는 가을 강좌 운영',
      '대한대 봉사단, 지역 아동 교육 프로그램 진행',
      '국제 협력 대학과 공동 학술포럼 개최'
    ],
    departments: ['인문대학', '사회과학대학', '자연과학대학', '공과대학', '경영대학', '예술체육대학', '융합대학'],
    majors: ['국어국문학과', '행정학과', '생명과학과', '컴퓨터공학과', '경영학부', '디자인학과', '데이터융합학부'],
    events: [
      ['중간시험 기간', '2026-10-20', '각 강의실'],
      ['전공 탐색 박람회', '2026-10-27', '중앙광장'],
      ['동계 계절학기 수강신청', '2026-11-09', '학사정보시스템'],
      ['개교기념 학술행사', '2026-11-19', '대학본부 대강당'],
      ['2학기 종강', '2026-12-18', '전 캠퍼스']
    ]
  },
  wonchang: {
    id: 'wonchang', name: '원창대학교', enName: 'WONCHANG UNIVERSITY',
    tagline: '지역을 품고 세계를 잇다', city: '경상남도 원창시 대학로 77',
    primary: '#6b2432', secondary: '#b7954c', logoMark: '原',
    heroTitle: '지역의 가능성이\n세계의 경쟁력이 되다',
    heroSubtitle: '현장과 연구를 연결하며 함께 성장하는 국립 원창대학교.',
    founded: '1975', phone: '055-210-1000',
    noticeTitles: [
      '2026학년도 2학기 중간고사 및 강의실 안내',
      '지역산업 연계 현장실습 참여학생 모집',
      '2027학년도 수시모집 면접고사 안내',
      '도서관 전자자료 이용 교육 신청',
      '2026학년도 겨울방학 해외연수 참가자 모집',
      '청년 취업 지원 프로그램 접수 안내',
      '장학재단 생활비 지원 대상자 공고',
      '학생회관 시설 개선 공사 안내',
      '학부 연구생 프로그램 설명회',
      '통학버스 노선 조정 안내',
      '대학원 신입생 모집 요강',
      '학사정보시스템 정기 점검 안내'
    ],
    newsTitles: [
      '원창대학교, 지역 기업과 산학협력 협약 체결',
      '해양융합연구소, 지속가능 항만 연구 착수',
      '학생 자율주행팀, 전국 경진대회 우수상',
      '시민 열린강좌에 지역 주민 300명 참여',
      '원창대 박물관, 지역사 특별전 개최',
      '국제교류처, 아시아 대학 교류주간 운영'
    ],
    departments: ['인문사회대학', '자연과학대학', '공과대학', '해양융합대학', '경상대학', '미래산업대학'],
    majors: ['역사문화학과', '사회복지학과', '환경과학과', '기계공학부', '해양시스템공학과', '경제학과'],
    events: [
      ['2학기 중간고사', '2026-10-21', '각 단과대학'],
      ['산학협력 채용박람회', '2026-10-29', '체육관'],
      ['수시모집 면접고사', '2026-11-14', '대학본부'],
      ['동계 계절학기 수강신청', '2026-11-25', '학사정보시스템'],
      ['2학기 종강', '2026-12-18', '전 캠퍼스']
    ]
  }
};

export const nav = [
  { label: '대학안내', href: '/about', children: [
    { label: '대학 소개', href: '/about' }, { label: '캠퍼스 안내', href: '/about#campus' }
  ] },
  { label: '입학안내', href: '/admissions', children: [
    { label: '모집 안내', href: '/admissions' }, { label: '입학 FAQ', href: '/faq' }
  ] },
  { label: '대학·대학원', href: '/colleges', children: [
    { label: '단과대학', href: '/colleges' }, { label: '학과 안내', href: '/colleges#departments' }
  ] },
  { label: '학사안내', href: '/academics', children: [
    { label: '학사제도', href: '/academics' }, { label: '학사일정', href: '/schedule' }
  ] },
  { label: '연구·산학', href: '/research', children: [
    { label: '연구 지원', href: '/research' }, { label: '산학협력', href: '/research#industry' }
  ] },
  { label: '대학생활', href: '/campus', children: [
    { label: '학생지원', href: '/campus' }, { label: '공지사항', href: '/notices' },
    { label: '자주 묻는 질문', href: '/faq' }
  ] },
  { label: '대학홍보', href: '/news', children: [
    { label: '대학 소식', href: '/news' }, { label: '공지사항', href: '/notices' }
  ] },
  { label: '시설대여', href: '/facilities', children: [
    { label: '대관 안내', href: '/facilities' }
  ] }
];

export const faqs = [
  { question: '입학 원서는 어디에서 접수하나요?', answer: '모집 시기별 원서접수 기간과 제출서류는 입학안내 공지에서 확인할 수 있습니다.' },
  { question: '수강신청 변경 기간은 언제인가요?', answer: '매 학기 학사일정에 공지되며 학사정보시스템에서 변경할 수 있습니다.' },
  { question: '장학금 신청 기준은 어떻게 확인하나요?', answer: '대학생활의 학생지원 안내와 공지사항에서 장학금별 신청 기준을 확인하세요.' },
  { question: '증명서는 어떻게 발급받나요?', answer: '로그인 후 마이페이지에서 관련 민원을 접수하거나 종합서비스센터를 방문하세요.' },
  { question: '캠퍼스 시설을 대여할 수 있나요?', answer: '시설대여 페이지의 이용 절차를 확인한 후 담당 부서에 문의하세요.' }
];

export function sectionFor(key, site) {
  const common = {
    about: {
      heading: '대학안내', intro: `${site.name}는 지식과 실천을 연결하는 배움의 공동체입니다.`,
      bodyHtml: `<p>${site.name}는 ${site.founded}년 설립 이래 교육과 연구, 지역사회 협력을 통해 새로운 가치를 만들어 왔습니다.</p><p>우리 대학은 학생 한 사람의 성장을 중심에 두고 학문 간 경계를 넘는 도전과 열린 협력을 지원합니다.</p>`,
      cards: [
        { title: '총장 인사말', description: '배움의 현장에서 시작되는 변화', href: '/about#vision' },
        { title: '대학 비전', description: '교육·연구·봉사의 중장기 방향', href: '/about#vision' },
        { title: '오시는 길', description: site.city, href: '/about#campus' }
      ]
    },
    admissions: {
      heading: '입학안내', intro: '새로운 가능성을 향한 첫걸음, 여러분의 도전을 기다립니다.',
      bodyHtml: '<p>수시·정시·편입학·외국인 특별전형의 모집요강과 전형 일정을 확인하세요. 전형별 지원 자격과 제출 서류는 모집 공지를 기준으로 합니다.</p>',
      cards: [
        { title: '수시모집', description: '학생부 종합·교과 전형 안내', href: '/notices' },
        { title: '정시모집', description: '모집단위 및 선발 일정', href: '/notices' },
        { title: '편입학', description: '일반·학사 편입학 안내', href: '/notices' },
        { title: '입학 FAQ', description: '지원 전에 자주 묻는 질문', href: '/faq' },
        ...(site.id === 'daehan' ? [
          { title: '협력기관 전형 진행조회', description: '협력기관 담당자를 위한 지원 현황 안내', href: '/admissions/partner' }
        ] : [])
      ]
    },
    colleges: {
      heading: '대학·대학원', intro: '기초 학문부터 융합 연구까지 폭넓은 배움이 이어집니다.',
      bodyHtml: '<p>각 단과대학은 전공 교육과 현장 경험을 연결하고, 대학원은 심화 연구와 전문 역량 개발을 지원합니다.</p>',
      cards: site.departments.map((title, index) => ({ title, description: `${site.majors[index] || '다양한 전공'} 등 학문 분야 안내`, href: '/colleges#departments' }))
    },
    academics: {
      heading: '학사안내', intro: '학업의 모든 단계에 필요한 정보를 한곳에서 확인하세요.',
      bodyHtml: '<p>학적, 수업, 졸업, 등록, 장학 및 국제교류에 관한 학사 기준은 학기별 공지와 학사일정을 통해 안내합니다.</p>',
      cards: [
        { title: '학적·수업', description: '휴학, 복학, 수강신청 안내', href: '/notices' },
        { title: '등록·장학', description: '등록금과 장학 제도', href: '/notices' },
        { title: '졸업·성적', description: '성적 평가와 졸업 요건', href: '/faq' },
        { title: '학사일정', description: '주요 학사 일정 확인', href: '/schedule' }
      ]
    },
    research: {
      heading: '연구·산학', intro: '현장의 질문을 연구의 성과로 연결합니다.',
      bodyHtml: '<p>연구지원센터와 산학협력단은 연구 과제의 기획부터 기술 이전, 창업과 지역 협력까지 함께합니다.</p>',
      cards: [
        { title: '연구지원', description: '연구과제·장비·윤리 지원', href: '/news' },
        { title: '산학협력', description: '기업과 대학의 공동 성장', href: '/news' },
        { title: '창업지원', description: '학생과 연구자의 아이디어 사업화', href: '/news' }
      ]
    },
    campus: {
      heading: '대학생활', intro: '강의실 밖의 경험이 배움의 폭을 넓힙니다.',
      bodyHtml: '<p>장학, 생활관, 동아리, 상담과 진로 지원 등 학생의 일상을 돕는 서비스를 제공합니다.</p>',
      cards: [
        { title: '학생지원', description: '장학·상담·진로 서비스', href: '/mypage' },
        { title: '공지사항', description: '캠퍼스의 최신 안내', href: '/notices' },
        { title: '학사일정', description: '학기별 주요 일정', href: '/schedule' },
        { title: '입학·학사 FAQ', description: '자주 묻는 질문과 답변', href: '/faq' },
        ...(site.id === 'wonchang' ? [
          { title: '교직원 모바일 업무지원', description: '학생지원 업무의 처리 현황 확인', href: '/staff/mobile' }
        ] : [])
      ]
    },
    facilities: {
      heading: '시설대여', intro: '캠퍼스 공간을 교육과 지역사회에 열어 둡니다.',
      bodyHtml: '<p>강당, 세미나실 및 야외공간은 운영 일정과 사용 목적에 따라 대여할 수 있습니다. 대관 신청은 시설 담당 부서에서 검토한 뒤 안내합니다.</p>',
      cards: [
        { title: '대강당', description: '학술행사와 공연을 위한 공간', href: '/faq' },
        { title: '세미나실', description: '소규모 회의와 교육 행사', href: '/faq' },
        { title: '신청 절차', description: '이용 문의 및 승인 절차', href: '/mypage' }
      ]
    }
  };
  return common[key];
}

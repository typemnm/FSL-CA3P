(() => {
  const searchToggle = document.querySelector('.search-toggle');
  const menuToggle = document.querySelector('.menu-toggle');
  const searchPanel = document.getElementById('global-search');
  const mobileNav = document.getElementById('mobile-nav');
  const searchForm = document.getElementById('global-search-form');
  const searchInput = document.getElementById('global-search-input');
  const searchResults = document.getElementById('search-results');
  let searchTimer;
  let searchController;

  function setPanel(button, panel, open, openLabel, closedLabel) {
    if (!button || !panel) return;
    panel.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    button.setAttribute('aria-label', open ? openLabel : closedLabel);
  }

  searchToggle?.addEventListener('click', () => {
    const open = searchPanel.hidden;
    setPanel(menuToggle, mobileNav, false, '전체 메뉴 닫기', '전체 메뉴 열기');
    setPanel(searchToggle, searchPanel, open, '통합검색 닫기', '통합검색 열기');
    if (open) searchInput?.focus();
  });

  menuToggle?.addEventListener('click', () => {
    const open = mobileNav.hidden;
    setPanel(searchToggle, searchPanel, false, '통합검색 닫기', '통합검색 열기');
    setPanel(menuToggle, mobileNav, open, '전체 메뉴 닫기', '전체 메뉴 열기');
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (searchPanel && !searchPanel.hidden) {
      setPanel(searchToggle, searchPanel, false, '통합검색 닫기', '통합검색 열기');
      searchToggle?.focus();
    } else if (mobileNav && !mobileNav.hidden) {
      setPanel(menuToggle, mobileNav, false, '전체 메뉴 닫기', '전체 메뉴 열기');
      menuToggle?.focus();
    }
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 1040) setPanel(menuToggle, mobileNav, false, '전체 메뉴 닫기', '전체 메뉴 열기');
  });

  function clearResults(message = '') {
    if (!searchResults) return;
    searchResults.replaceChildren();
    if (message) {
      const paragraph = document.createElement('p');
      paragraph.textContent = message;
      searchResults.append(paragraph);
    }
  }

  function resultUrl(item) {
    if (typeof item.url === 'string' && item.url.startsWith('/')) return item.url;
    if (typeof item.href === 'string' && item.href.startsWith('/')) return item.href;
    const board = item.type === 'news' ? 'news' : 'notices';
    return item.id == null ? `/${board}` : `/${board}/${encodeURIComponent(item.id)}`;
  }

  function renderResults(items) {
    clearResults();
    if (!items.length) {
      clearResults('검색 결과가 없습니다. 다른 검색어를 입력해 보세요.');
      return;
    }
    const fragment = document.createDocumentFragment();
    items.slice(0, 8).forEach((item) => {
      const link = document.createElement('a');
      link.href = resultUrl(item);
      const type = document.createElement('span');
      type.className = 'search-type';
      type.textContent = item.type === 'news' ? '대학 소식' : '공지사항';
      const title = document.createElement('span');
      title.textContent = item.title || '제목 없음';
      link.append(type, title);
      fragment.append(link);
    });
    searchResults.append(fragment);
  }

  async function performSearch(query, fallbackOnError = false) {
    if (!query || query.trim().length < 2) {
      clearResults('두 글자 이상 입력하면 검색 결과가 표시됩니다.');
      return;
    }
    searchController?.abort();
    searchController = new AbortController();
    clearResults('검색 중입니다…');
    try {
      const response = await fetch(`/api/search?q=${encodeURIComponent(query.trim())}`, {
        headers: { Accept: 'application/json' },
        signal: searchController.signal
      });
      if (!response.ok) throw new Error('검색 요청 실패');
      const data = await response.json();
      const items = Array.isArray(data) ? data : (data.results || data.posts || []);
      renderResults(Array.isArray(items) ? items : []);
    } catch (error) {
      if (error.name === 'AbortError') return;
      if (fallbackOnError) {
        window.location.assign(`/notices?q=${encodeURIComponent(query.trim())}`);
      } else {
        clearResults('검색을 완료하지 못했습니다. 검색 버튼을 눌러 다시 시도해 주세요.');
      }
    }
  }

  searchInput?.addEventListener('input', () => {
    window.clearTimeout(searchTimer);
    const query = searchInput.value;
    if (query.trim().length < 2) {
      searchController?.abort();
      clearResults(query ? '두 글자 이상 입력하면 검색 결과가 표시됩니다.' : '');
      return;
    }
    searchTimer = window.setTimeout(() => performSearch(query), 280);
  });

  searchForm?.addEventListener('submit', (event) => {
    event.preventDefault();
    window.clearTimeout(searchTimer);
    performSearch(searchInput.value, true);
  });

  document.querySelectorAll('.delete-form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm('이 게시물을 삭제하시겠습니까?')) event.preventDefault();
    });
  });
})();

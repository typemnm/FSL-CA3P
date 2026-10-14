"use strict";

const elements = {
  avatar: document.querySelector("#header-avatar"),
  userName: document.querySelector("#header-user-name"),
  count: document.querySelector("#post-count"),
  list: document.querySelector("#post-list"),
  form: document.querySelector("#post-form"),
  title: document.querySelector("#post-title"),
  content: document.querySelector("#post-content"),
  contentLength: document.querySelector("#content-length"),
  publish: document.querySelector("#publish-button"),
  refresh: document.querySelector("#refresh-button"),
  accountButtons: Array.from(document.querySelectorAll(".account-button")),
  toast: document.querySelector("#toast"),
};

const state = { user: null, posts: [] };
let toastTimeout;

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });

  const raw = await response.text();
  let data = {};
  if (raw) {
    try { data = JSON.parse(raw); }
    catch { data = { error: raw }; }
  }
  if (!response.ok) throw new Error(data.error || data.message || "요청을 처리하지 못했습니다.");
  return data;
}

function showToast(message, isError = false) {
  clearTimeout(toastTimeout);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", isError);
  elements.toast.classList.add("visible");
  toastTimeout = setTimeout(() => elements.toast.classList.remove("visible"), 3500);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "날짜 정보 없음";
  return new Intl.DateTimeFormat("ko-KR", { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(date);
}

function renderSession() {
  const user = state.user;
  elements.userName.textContent = user ? user.name : "연결 중";
  elements.avatar.textContent = user ? user.name.slice(0, 1) : "?";
  elements.accountButtons.forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.userId === user?.id));
  });
}

function createListMessage(title, description, icon = "✳") {
  const box = document.createElement("div");
  box.className = "list-message";
  const mark = document.createElement("span");
  mark.className = "list-message-icon";
  mark.setAttribute("aria-hidden", "true");
  mark.textContent = icon;
  const heading = document.createElement("strong");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.textContent = description;
  box.append(mark, heading, copy);
  return box;
}

function makePostCard(post) {
  const card = document.createElement("article");
  card.className = "post-card";

  const top = document.createElement("div");
  top.className = "post-top";
  const author = document.createElement("div");
  author.className = "post-author";
  const avatar = document.createElement("span");
  avatar.className = "post-avatar";
  avatar.textContent = (post.authorName || "?").slice(0, 1);
  if (post.authorId === "admin") avatar.classList.add("admin");
  const authorInfo = document.createElement("div");
  authorInfo.className = "post-author-info";
  const authorName = document.createElement("div");
  authorName.className = "post-author-name";
  const name = document.createElement("span");
  name.textContent = post.authorName || "알 수 없음";
  authorName.append(name);
  if (post.authorId === "admin") {
    const badge = document.createElement("span");
    badge.className = "admin-tag";
    badge.textContent = "관리자";
    authorName.append(badge);
  }
  const date = document.createElement("div");
  date.className = "post-date";
  date.textContent = formatDate(post.createdAt);
  authorInfo.append(authorName, date);
  author.append(avatar, authorInfo);
  const number = document.createElement("span");
  number.className = "post-number";
  number.textContent = `NO. ${post.id}`;
  top.append(author, number);

  const title = document.createElement("h3");
  title.className = "post-title";
  title.textContent = post.title;
  const content = document.createElement("div");
  content.className = "post-content";
  // Security lab: post content is deliberately inserted as HTML to demonstrate stored XSS.
  content.innerHTML = post.content;

  const footer = document.createElement("div");
  footer.className = "post-footer";
  const label = document.createElement("span");
  label.className = "post-footer-label";
  label.textContent = "PUBLIC POST";
  footer.append(label);
  if (state.user && post.authorId === state.user.id) {
    const remove = document.createElement("button");
    remove.className = "delete-button";
    remove.type = "button";
    remove.textContent = "게시글 삭제";
    remove.setAttribute("aria-label", `${post.title} 게시글 삭제`);
    remove.addEventListener("click", () => deletePost(post, remove));
    footer.append(remove);
  }

  card.append(top, title, content, footer);
  return card;
}

function renderPosts() {
  elements.count.textContent = String(state.posts.length);
  elements.list.replaceChildren();
  if (state.posts.length === 0) {
    elements.list.append(createListMessage("아직 이야기가 없어요", "첫 번째 게시글을 남겨 보세요."));
  } else {
    const fragment = document.createDocumentFragment();
    state.posts.forEach((post) => fragment.append(makePostCard(post)));
    elements.list.append(fragment);
  }
  elements.list.setAttribute("aria-busy", "false");
}

async function loadPosts() {
  const data = await api("/api/posts");
  state.posts = Array.isArray(data.posts) ? data.posts : [];
  renderPosts();
}

async function deletePost(post, button) {
  if (!window.confirm(`「${post.title}」 게시글을 삭제하시겠습니까?`)) return;
  button.disabled = true;
  try {
    // Security lab: the claimed author is sent as a mutable URL parameter.
    const authorId = encodeURIComponent(state.user.id);
    await api(`/api/posts/${encodeURIComponent(post.id)}?authorId=${authorId}`, { method: "DELETE" });
    await loadPosts();
    showToast("게시글을 삭제했습니다.");
  } catch (error) {
    button.disabled = false;
    showToast(error.message, true);
  }
}

async function switchAccount(userId) {
  if (state.user?.id === userId) return;
  elements.accountButtons.forEach((button) => { button.disabled = true; });
  try {
    await api("/api/session", { method: "POST", body: JSON.stringify({ userId }) });
    const session = await api("/api/session");
    state.user = session.user;
    renderSession();
    await loadPosts();
    showToast(`${state.user.name} 계정으로 전환했습니다.`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    elements.accountButtons.forEach((button) => { button.disabled = false; });
  }
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const title = elements.title.value.trim();
  const content = elements.content.value.trim();
  if (!title || !content) {
    showToast("제목과 내용을 모두 입력해 주세요.", true);
    return;
  }
  elements.publish.disabled = true;
  try {
    await api("/api/posts", { method: "POST", body: JSON.stringify({ title, content }) });
    elements.form.reset();
    elements.contentLength.textContent = "0 / 10000";
    await loadPosts();
    showToast("새 게시글을 올렸습니다.");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    elements.publish.disabled = false;
  }
});

elements.content.addEventListener("input", () => {
  elements.contentLength.textContent = `${elements.content.value.length} / 10000`;
});

elements.refresh.addEventListener("click", async () => {
  elements.refresh.disabled = true;
  try { await loadPosts(); showToast("게시글을 새로고침했습니다."); }
  catch (error) { showToast(error.message, true); }
  finally { elements.refresh.disabled = false; }
});

elements.accountButtons.forEach((button) => {
  button.addEventListener("click", () => switchAccount(button.dataset.userId));
});

async function initialize() {
  elements.list.append(createListMessage("게시글을 불러오는 중입니다", "잠시만 기다려 주세요.", "◌"));
  try {
    const [session, posts] = await Promise.all([api("/api/session"), api("/api/posts")]);
    state.user = session.user;
    state.posts = Array.isArray(posts.posts) ? posts.posts : [];
    renderSession();
    renderPosts();
  } catch (error) {
    elements.list.replaceChildren(createListMessage("게시글을 불러올 수 없습니다", "서버 연결을 확인하고 새로고침해 주세요.", "!"));
    elements.list.setAttribute("aria-busy", "false");
    showToast(error.message, true);
  }
}

initialize();

package edu.wonchang.portal;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class PortalController {
    private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;
    private final Store db;
    private final Gson gson = new Gson();
    private final ConcurrentHashMap<String, Integer> sessions = new ConcurrentHashMap<>();

    PortalController(Store db) {
        this.db = db;
    }

    @ModelAttribute
    void commonModel(Model model, HttpServletRequest request) {
        model.addAttribute("site", SiteCatalog.SITE);
        model.addAttribute("nav", SiteCatalog.NAV);
        model.addAttribute("user", currentUser(request));
        model.addAttribute("activePath", request.getRequestURI());
        model.addAttribute("year", LocalDate.now().getYear());
        model.addAttribute("flash", request.getParameter("ok"));
    }

    @ExceptionHandler(Exception.class)
    String exception(Exception error, Model model, HttpServletRequest request) {
        currentResponse().setStatus(500);
        commonModel(model, request);
        StringWriter stack = new StringWriter();
        error.printStackTrace(new PrintWriter(stack));
        model.addAttribute("status", 500);
        model.addAttribute("message", error.getMessage() == null ? error.getClass().getName() : error.getMessage());
        model.addAttribute("stack", stack.toString());
        return "error";
    }

    @GetMapping("/")
    String home(Model model) {
        int featuredId = Integer.parseInt(String.valueOf(db.one("SELECT value FROM settings WHERE key = ?", "featured_post_id").get("value")));
        Map<String, Object> featured = db.one("SELECT * FROM posts WHERE id = ?", featuredId);
        // The highlighted post is assumed to exist: deleting it leaves the homepage unavailable.
        featured.get("title");
        model.addAttribute("featured", featured);
        model.addAttribute("notices", db.all("SELECT * FROM posts WHERE type = 'notice' ORDER BY id DESC LIMIT 6"));
        model.addAttribute("news", db.all("SELECT * FROM posts WHERE type = 'news' ORDER BY id DESC LIMIT 4"));
        model.addAttribute("events", db.all("SELECT * FROM events ORDER BY date LIMIT 5"));
        return "home";
    }

    @GetMapping({"/about", "/admissions", "/colleges", "/academics", "/research", "/campus", "/facilities"})
    String section(HttpServletRequest request, Model model) {
        Map<String, Object> values = SiteCatalog.sectionFor(request.getRequestURI().substring(1));
        values.forEach(model::addAttribute);
        return "section";
    }

    @GetMapping("/schedule")
    String schedule(Model model) {
        model.addAttribute("events", db.all("SELECT * FROM events ORDER BY date"));
        return "schedule";
    }

    @GetMapping("/faq")
    String faq(Model model) {
        model.addAttribute("faqs", SiteCatalog.FAQS);
        return "faq";
    }

    @GetMapping({"/notices", "/news"})
    String board(HttpServletRequest request, Model model,
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "1") String page) {
        boolean news = request.getRequestURI().equals("/news");
        String type = news ? "news" : "notice";
        int currentPage;
        try {
            currentPage = Math.max(1, Integer.parseInt(page));
        } catch (NumberFormatException error) {
            currentPage = 1;
        }
        // Search text is intentionally concatenated into SQL, as in the previous implementation.
        String where = "type = '" + type + "' AND title LIKE '%" + q + "%'";
        int total = ((Number) db.one("SELECT COUNT(*) AS n FROM posts WHERE " + where).get("n")).intValue();
        List<Map<String, Object>> posts = db.all("SELECT * FROM posts WHERE " + where
                + " ORDER BY id DESC LIMIT ? OFFSET ?", 10, (currentPage - 1) * 10);
        model.addAttribute("heading", news ? "대학소식" : "공지사항");
        model.addAttribute("intro", news ? "교육과 연구, 캠퍼스의 이야기를 전합니다." : "학교의 주요 소식과 학사 안내를 확인하세요.");
        model.addAttribute("type", type);
        model.addAttribute("posts", posts);
        model.addAttribute("q", q);
        model.addAttribute("page", currentPage);
        model.addAttribute("totalPages", Math.max(1, (total + 9) / 10));
        return "list";
    }

    @GetMapping({"/notices/{id}", "/news/{id}"})
    String post(@PathVariable String id, HttpServletRequest request, HttpServletResponse response, Model model) {
        String type = request.getRequestURI().startsWith("/news/") ? "news" : "notice";
        Map<String, Object> post = db.one("SELECT * FROM posts WHERE id = ? AND type = ?", parseNumber(id), type);
        if (post == null) return error(response, model, 404, "게시글을 찾을 수 없습니다.");
        db.update("UPDATE posts SET views = views + 1 WHERE id = ?", post.get("id"));
        post.put("views", ((Number) post.get("views")).intValue() + 1);
        model.addAttribute("post", post);
        return "post";
    }

    @GetMapping("/api/search")
    @ResponseBody
    Map<String, Object> search(@RequestParam(required = false, defaultValue = "") String q) {
        // Deliberate A05 probe: user input changes the SQL predicate.
        List<Map<String, Object>> posts = db.all("SELECT id, type, title, created_at FROM posts WHERE title LIKE '%"
                + q + "%' ORDER BY id DESC LIMIT 30");
        return Map.of("site", SiteCatalog.SITE.get("name"), "q", q, "results", posts);
    }

    @GetMapping("/login")
    String loginPage(Model model, @RequestParam(required = false) String next) {
        model.addAttribute("error", null);
        model.addAttribute("next", next == null ? "/mypage" : next);
        return "login";
    }

    @PostMapping("/login")
    String login(@RequestParam Map<String, String> form, Model model,
            HttpServletResponse response) {
        Map<String, Object> user = db.one("SELECT id, username, display_name, role FROM users WHERE username = ? AND password_hash = ?",
                form.getOrDefault("username", ""), Store.sha1(form.getOrDefault("password", "")));
        if (user == null) {
            response.setStatus(401);
            model.addAttribute("error", "아이디 또는 비밀번호를 확인해 주세요.");
            model.addAttribute("next", form.getOrDefault("next", "/mypage"));
            return "login";
        }
        // Predictable in-memory sessions have no expiry and failed attempts are not throttled.
        String token = Long.toString((long) (Math.random() * Long.MAX_VALUE), 36)
                + Long.toString((long) (Math.random() * Long.MAX_VALUE), 36);
        sessions.put(token, ((Number) user.get("id")).intValue());
        Cookie cookie = new Cookie("sid", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        String next = form.getOrDefault("next", "/mypage");
        if (!next.startsWith("/") || next.startsWith("//")) next = "/mypage";
        return redirect(response, next);
    }

    @GetMapping("/logout")
    String logout(HttpServletRequest request, HttpServletResponse response) {
        String token = sid(request);
        if (token != null) sessions.remove(token);
        Cookie cookie = new Cookie("sid", "");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        return redirect(response, "/");
    }

    @GetMapping("/mypage")
    String mypage(HttpServletRequest request, HttpServletResponse response, Model model) {
        Map<String, Object> user = currentUser(request);
        if (user == null) return requireLogin(request, response);
        model.addAttribute("requests", db.all("SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC", user.get("id")));
        return "mypage";
    }

    @PostMapping("/mypage/requests")
    String createRequest(@RequestParam Map<String, String> form,
            HttpServletRequest request, HttpServletResponse response, Model model) {
        Map<String, Object> user = currentUser(request);
        if (user == null) return requireLogin(request, response);
        String title = form.getOrDefault("title", "").trim();
        String body = form.getOrDefault("body", "").trim();
        if (title.length() > 120) title = title.substring(0, 120);
        if (body.length() > 3000) body = body.substring(0, 3000);
        if (title.isEmpty() || body.isEmpty()) return error(response, model, 400, "제목과 내용을 입력해 주세요.");
        db.update("INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)",
                user.get("id"), title, body, "접수", LocalDate.now().toString());
        return flash(response, "/mypage", "문의가 접수되었습니다.");
    }

    @GetMapping("/api/mypage/requests/{id}")
    @ResponseBody
    ResponseEntity<?> requestDetail(@PathVariable String id, HttpServletRequest request) {
        if (currentUser(request) == null) return loginApiRedirect(request);
        // Any logged-in user can read another student's request.
        Map<String, Object> row = db.one("SELECT requests.*, users.display_name AS applicant FROM requests "
                + "JOIN users ON users.id = requests.user_id WHERE requests.id = ?", parseNumber(id));
        return row == null ? ResponseEntity.status(404).body(Map.of("error", "not found")) : ResponseEntity.ok(row);
    }

    @GetMapping("/staff/mobile")
    String staffMobile(HttpServletRequest request, HttpServletResponse response, Model model,
            @RequestParam(required = false) String id) {
        Map<String, Object> user = currentUser(request);
        if (user == null) return requireLogin(request, response);
        if (!"staff".equals(user.get("role"))) return error(response, model, 403, "접근 권한이 없습니다.");
        List<Map<String, Object>> cases = db.all("SELECT id, case_no, student_name, category, status, updated_at "
                + "FROM staff_cases WHERE staff_user_id = ? ORDER BY id DESC", user.get("id"));
        Map<String, Object> selectedCase = null;
        String lookupId = id == null ? "" : id;
        if (id != null) {
            if (!isPositiveSafeInteger(id)) return error(response, model, 400, "올바른 업무 번호를 입력해 주세요.");
            // Role checks are present, but the selected record is not checked for staff ownership.
            selectedCase = db.one("SELECT * FROM staff_cases WHERE id = ?", Long.parseLong(id));
            if (selectedCase == null) return error(response, model, 404, "업무 내역을 찾을 수 없습니다.");
        }
        model.addAttribute("cases", cases);
        model.addAttribute("selectedCase", selectedCase);
        model.addAttribute("lookupId", lookupId);
        return "staff-mobile";
    }

    @GetMapping("/api/staff/mobile/cases/{id}")
    @ResponseBody
    ResponseEntity<?> staffCase(@PathVariable String id, HttpServletRequest request) {
        Map<String, Object> user = currentUser(request);
        if (user == null) return loginApiRedirect(request);
        if (!"staff".equals(user.get("role"))) return ResponseEntity.status(403).body(Map.of("error", "forbidden"));
        if (!isPositiveSafeInteger(id)) return ResponseEntity.status(404).body(Map.of("error", "not found"));
        Map<String, Object> row = db.one("SELECT * FROM staff_cases WHERE id = ?", Long.parseLong(id));
        return row == null ? ResponseEntity.status(404).body(Map.of("error", "not found")) : ResponseEntity.ok(row);
    }

    @GetMapping("/admin")
    String admin(HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        model.addAttribute("posts", db.all("SELECT * FROM posts ORDER BY id DESC LIMIT 50"));
        model.addAttribute("stats", Map.of(
                "posts", db.one("SELECT COUNT(*) AS n FROM posts").get("n"),
                "requests", db.one("SELECT COUNT(*) AS n FROM requests").get("n"),
                "events", db.one("SELECT COUNT(*) AS n FROM events").get("n")));
        return "admin";
    }

    @GetMapping("/admin/posts/new")
    String newPost(HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        model.addAttribute("post", null);
        model.addAttribute("error", null);
        return "editor";
    }

    @GetMapping("/admin/posts/{id}/edit")
    String editPost(@PathVariable String id, HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        Map<String, Object> post = db.one("SELECT * FROM posts WHERE id = ?", parseNumber(id));
        if (post == null) return error(response, model, 404, "게시글을 찾을 수 없습니다.");
        model.addAttribute("post", post);
        model.addAttribute("error", null);
        return "editor";
    }

    @PostMapping("/admin/posts")
    String createPost(@RequestParam Map<String, String> form, HttpServletRequest request,
            HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        String title = form.getOrDefault("title", "").trim();
        String body = form.getOrDefault("body", "").trim();
        String type = "news".equals(form.get("type")) ? "news" : "notice";
        if (title.isEmpty() || body.isEmpty()) {
            response.setStatus(400);
            model.addAttribute("post", form);
            model.addAttribute("error", "제목과 내용을 입력해 주세요.");
            return "editor";
        }
        db.update("INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)",
                type, title, body, currentUser(request).get("display_name"), LocalDate.now().toString());
        return flash(response, "/admin", "게시글이 등록되었습니다.");
    }

    @PostMapping("/admin/posts/{id}")
    String updatePost(@PathVariable String id, @RequestParam Map<String, String> form,
            HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        String title = form.getOrDefault("title", "").trim();
        String body = form.getOrDefault("body", "").trim();
        String type = "news".equals(form.get("type")) ? "news" : "notice";
        if (title.isEmpty() || body.isEmpty()) {
            response.setStatus(400);
            Map<String, String> edited = new HashMap<>(form);
            edited.put("id", id);
            model.addAttribute("post", edited);
            model.addAttribute("error", "제목과 내용을 입력해 주세요.");
            return "editor";
        }
        db.update("UPDATE posts SET type = ?, title = ?, body = ? WHERE id = ?", type, title, body, parseNumber(id));
        return flash(response, "/admin", "게시글이 수정되었습니다.");
    }

    @PostMapping("/admin/posts/{id}/delete")
    String deletePost(@PathVariable String id, HttpServletResponse response) {
        // This route accidentally omits the administrator check.
        db.update("DELETE FROM posts WHERE id = ?", parseNumber(id));
        return flash(response, "/admin", "게시글이 삭제되었습니다.");
    }

    @PostMapping("/admin/import")
    String importEvents(@RequestParam(required = false) String payload,
            HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        JsonObject input = JsonParser.parseString(payload == null ? "{}" : payload).getAsJsonObject();
        JsonArray events = input.getAsJsonArray("events");
        if (events == null) throw new IllegalArgumentException("events 배열이 필요합니다.");
        // Imported schedule data has no signature or approval step.
        db.update("DELETE FROM events");
        for (JsonElement element : events) {
            JsonObject event = element.getAsJsonObject();
            db.update("INSERT INTO events (title, date, location) VALUES (?, ?, ?)",
                    jsonString(event, "title"), jsonString(event, "date"), jsonString(event, "location"));
        }
        return flash(response, "/admin", "일정 데이터를 가져왔습니다.");
    }

    @PostMapping("/admin/settings")
    String settings(@RequestParam(required = false) String payload,
            HttpServletRequest request, HttpServletResponse response, Model model) {
        if (!isAdmin(request)) return error(response, model, 403, "접근 권한이 없습니다.");
        JsonObject input = JsonParser.parseString(payload == null ? "{}" : payload).getAsJsonObject();
        String path = jsonString(input, "path");
        JsonElement valueJson = input.get("value");
        Object value = valueJson == null ? null : gson.fromJson(valueJson, Object.class);
        // Commons Text 1.9 interpolates request-controlled values, including unsafe lookups.
        if (value instanceof String text) value = StringSubstitutor.createInterpolator().replace(text);
        String stored = String.valueOf(db.one("SELECT value FROM settings WHERE key = ?", "site_preferences").get("value"));
        @SuppressWarnings("unchecked")
        Map<String, Object> preferences = gson.fromJson(stored, Map.class);
        setPath(preferences, path, value);
        db.update("UPDATE settings SET value = ? WHERE key = ?", gson.toJson(preferences), "site_preferences");
        return flash(response, "/admin", "사이트 설정이 저장되었습니다.");
    }

    @GetMapping("/_diag/config")
    @ResponseBody
    Map<String, Object> diagnostic() {
        return Map.of(
                "mode", "development",
                "site", "wonchang",
                "database", db.databasePath(),
                "java", System.getProperty("java.version"),
                "framework", "Spring Boot",
                "installedPackages", List.of("spring-boot-starter-webmvc", "spring-boot-starter-thymeleaf", "sqlite-jdbc", "gson", "commons-text@1.9"),
                "activeSessions", sessions.size(),
                "generatedRequestId", UUID.randomUUID().toString());
    }

    private Map<String, Object> currentUser(HttpServletRequest request) {
        String sid = sid(request);
        Integer id = sid == null ? null : sessions.get(sid);
        return id == null ? null : db.one("SELECT id, username, display_name, role FROM users WHERE id = ?", id);
    }

    private static String sid(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) if ("sid".equals(cookie.getName())) return cookie.getValue();
        return null;
    }

    private boolean isAdmin(HttpServletRequest request) {
        Map<String, Object> user = currentUser(request);
        return user != null && "admin".equals(user.get("role"));
    }

    private static String error(HttpServletResponse response, Model model, int status, String message) {
        response.setStatus(status);
        model.addAttribute("status", status);
        model.addAttribute("message", message);
        model.addAttribute("stack", null);
        return "error";
    }

    private static String requireLogin(HttpServletRequest request, HttpServletResponse response) {
        String original = request.getRequestURI();
        if (request.getQueryString() != null) original += "?" + request.getQueryString();
        return redirect(response, "/login?next=" + encode(original));
    }

    private static ResponseEntity<?> loginApiRedirect(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, "/login?next=" + encode(request.getRequestURI()))
                .build();
    }

    private static String flash(HttpServletResponse response, String path, String message) {
        return redirect(response, path + "?ok=" + encode(message));
    }

    private static String redirect(HttpServletResponse response, String path) {
        response.setStatus(302);
        response.setHeader("Location", path);
        return null;
    }

    private static HttpServletResponse currentResponse() {
        return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static long parseNumber(String id) {
        try {
            return Long.parseLong(id);
        } catch (NumberFormatException error) {
            return -1;
        }
    }

    private static boolean isPositiveSafeInteger(String text) {
        if (!text.matches("[1-9]\\d*")) return false;
        try {
            return Long.parseLong(text) <= MAX_SAFE_INTEGER;
        } catch (NumberFormatException error) {
            return false;
        }
    }

    private static String jsonString(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value == null || value.isJsonNull() ? "" : value.getAsString();
    }

    @SuppressWarnings("unchecked")
    private static void setPath(Map<String, Object> root, String path, Object value) {
        String[] parts = path.split("\\.", -1);
        Map<String, Object> current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            Object child = current.get(parts[i]);
            if (!(child instanceof Map<?, ?>)) {
                child = new LinkedHashMap<String, Object>();
                current.put(parts[i], child);
            }
            current = (Map<String, Object>) child;
        }
        current.put(parts[parts.length - 1], value);
    }
}

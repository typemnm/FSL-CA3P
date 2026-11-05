package edu.wonchang.portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
final class Store {
    private final Connection connection;
    private final String databasePath;

    Store(@Value("${wonchang.database.path:data/wonchang.sqlite}") String path) {
        databasePath = path;
        try {
            if (!"1".equals(System.getenv("LAB_MEMORY_DB"))) {
                Path parent = Path.of(path).toAbsolutePath().getParent();
                if (parent != null) Files.createDirectories(parent);
            }
            connection = DriverManager.getConnection("jdbc:sqlite:" +
                    ("1".equals(System.getenv("LAB_MEMORY_DB")) ? ":memory:" : path));
            initialize();
        } catch (SQLException | IOException error) {
            throw new IllegalStateException("Could not initialize Wonchang SQLite database", error);
        }
    }

    String databasePath() {
        return databasePath;
    }

    synchronized Map<String, Object> one(String sql, Object... args) {
        try (PreparedStatement statement = prepare(sql, args);
                ResultSet result = statement.executeQuery()) {
            return result.next() ? row(result) : null;
        } catch (SQLException error) {
            throw new IllegalStateException(error);
        }
    }

    synchronized List<Map<String, Object>> all(String sql, Object... args) {
        try (PreparedStatement statement = prepare(sql, args);
                ResultSet result = statement.executeQuery()) {
            List<Map<String, Object>> rows = new ArrayList<>();
            while (result.next()) rows.add(row(result));
            return rows;
        } catch (SQLException error) {
            throw new IllegalStateException(error);
        }
    }

    synchronized int update(String sql, Object... args) {
        try (PreparedStatement statement = prepare(sql, args)) {
            return statement.executeUpdate();
        } catch (SQLException error) {
            throw new IllegalStateException(error);
        }
    }

    private PreparedStatement prepare(String sql, Object... args) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        try {
            for (int i = 0; i < args.length; i++) statement.setObject(i + 1, args[i]);
            return statement;
        } catch (SQLException error) {
            statement.close();
            throw error;
        }
    }

    private static Map<String, Object> row(ResultSet result) throws SQLException {
        ResultSetMetaData meta = result.getMetaData();
        Map<String, Object> row = new LinkedHashMap<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            row.put(meta.getColumnLabel(i), result.getObject(i));
        }
        return row;
    }

    private void execute(String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private int count(String table) {
        return ((Number) one("SELECT COUNT(*) AS n FROM " + table).get("n")).intValue();
    }

    private void initialize() throws SQLException {
        execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL)");
        execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0)");
        execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, date TEXT NOT NULL, location TEXT NOT NULL)");
        execute("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)");
        execute("CREATE TABLE IF NOT EXISTS staff_cases (id INTEGER PRIMARY KEY, staff_user_id INTEGER NOT NULL, case_no TEXT UNIQUE NOT NULL, student_name TEXT, student_no TEXT, category TEXT, contact TEXT, status TEXT, note TEXT, updated_at TEXT)");
        execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)");

        if (count("users") == 0) {
            update("INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)", "admin", "대학 관리자", "admin", sha1("admin1234"));
            update("INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)", "student1", "김가람", "student", sha1("Welcome2026"));
            update("INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)", "student2", "이누리", "student", sha1("Welcome2026"));
        }
        // Independent inserts migrate previously initialized Docker volumes without replacing their data.
        update("INSERT OR IGNORE INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)", "staff1", "학생지원팀 직원 최나래", "staff", sha1("Staff2026"));
        update("INSERT OR IGNORE INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)", "staff2", "학생지원팀 직원 정하늘", "staff", sha1("Staff2026"));
        int staff1 = ((Number) one("SELECT id FROM users WHERE username = ?", "staff1").get("id")).intValue();
        int staff2 = ((Number) one("SELECT id FROM users WHERE username = ?", "staff2").get("id")).intValue();
        Object[][] cases = {
                { staff1, "WC-MOB-2026-001", "한서우", "20260001", "장학 지급 확인", "case01@example.invalid", "검토 중", "장학 지급 서류의 확인 절차가 진행 중입니다.", "2026-10-16" },
                { staff1, "WC-MOB-2026-002", "강민재", "20260002", "등록금 납부 확인", "case02@example.invalid", "보완 요청", "제출된 납부 자료의 추가 확인이 필요합니다.", "2026-10-17" },
                { staff2, "WC-MOB-2026-003", "오다인", "20260003", "현장실습 지원", "case03@example.invalid", "접수", "현장실습 신청 자료를 접수했습니다.", "2026-10-15" },
                { staff2, "WC-MOB-2026-004", "백유진", "20260004", "생활지원 상담", "case04@example.invalid", "검토 중", "학생지원팀에서 상담 요청을 검토하고 있습니다.", "2026-10-18" }
        };
        for (Object[] item : cases) {
            update("INSERT OR IGNORE INTO staff_cases (staff_user_id, case_no, student_name, student_no, category, contact, status, note, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", item);
        }

        if (count("posts") == 0) {
            for (int i = 0; i < SiteCatalog.NOTICE_TITLES.size(); i++) {
                String title = SiteCatalog.NOTICE_TITLES.get(i);
                String body = title + "\n\n원창대학교 학생과 교직원 여러분께 안내드립니다. 관련 일정과 세부 내용을 확인해 주시기 바랍니다.\n\n대상: "
                        + (i % 2 == 1 ? "재학생 및 대학원생" : "전체 구성원")
                        + "\n문의: 학사지원과 (055-210-1000)\n\n원활한 학사 운영을 위해 많은 관심과 협조 부탁드립니다.";
                update("INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)",
                        "notice", title, body, i % 3 == 0 ? "입학처" : "학사지원과",
                        LocalDate.parse("2026-10-17").minusDays(i).toString());
            }
            for (int i = 0; i < SiteCatalog.NEWS_TITLES.size(); i++) {
                String title = SiteCatalog.NEWS_TITLES.get(i);
                String body = title + "\n\n원창대학교는 교육과 연구의 성과를 지역사회와 함께 나누고 있습니다. 이번 행사는 구성원과 지역 기관이 참여해 새로운 협력 기회를 모색했습니다.\n\n자세한 소식은 대학홍보실로 문의해 주시기 바랍니다.";
                update("INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)",
                        "news", title, body, "대학홍보실",
                        LocalDate.parse("2026-10-15").minusDays(i * 3L).toString());
            }
        }
        if (count("events") == 0) {
            for (List<String> event : SiteCatalog.EVENTS) {
                update("INSERT INTO events (title, date, location) VALUES (?, ?, ?)", event.get(0), event.get(1), event.get(2));
            }
        }
        if (count("requests") == 0) {
            update("INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)",
                    2, "재학증명서 발급 문의", "온라인 증명서 발급 절차를 알고 싶습니다.", "답변 완료", "2026-10-12");
            update("INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)",
                    3, "학생생활관 신청 문의", "겨울학기 입사 일정을 확인하고 싶습니다.", "접수", "2026-10-14");
        }
        if (one("SELECT key FROM settings WHERE key = ?", "featured_post_id") == null) {
            update("INSERT INTO settings (key, value) VALUES (?, ?)", "featured_post_id", "1");
        }
        if (one("SELECT key FROM settings WHERE key = ?", "site_preferences") == null) {
            update("INSERT INTO settings (key, value) VALUES (?, ?)", "site_preferences", "{\"theme\":{\"label\":\"지역을 품고 세계를 잇다\"}}");
        }
    }

    static String sha1(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder text = new StringBuilder();
            for (byte b : digest) text.append(String.format("%02x", b & 0xff));
            return text.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }
}

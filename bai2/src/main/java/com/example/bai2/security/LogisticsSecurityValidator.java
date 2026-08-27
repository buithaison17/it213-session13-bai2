package com.example.bai2.security;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogisticsSecurityValidator {

    private static final Pattern FORBIDDEN_SQL_PATTERN = Pattern.compile(
            "\\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|EXEC|EXECUTE|CREATE|REPLACE)\\b|;|--",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern LIMIT_PATTERN = Pattern.compile(
            "\\bLIMIT\\s+(\\d+)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Lớp phòng vệ 1: Kiểm tra và chuẩn hóa câu truy vấn SQL an toàn.
     */
    public static String validateSql(String rawSql) {
        if (rawSql == null || rawSql.isBlank()) {
            throw new SecurityException("SQL query cannot be null or empty.");
        }

        String trimmedSql = rawSql.trim();

        // 1. Kiểm tra từ khóa bắt đầu phải là SELECT
        if (!trimmedSql.toUpperCase().startsWith("SELECT")) {
            throw new SecurityException("Security Violation: Only SELECT queries are permitted.");
        }

        // 2. Chặn các từ khóa phá hoại, comment SQL và dấu chấm phẩy
        if (FORBIDDEN_SQL_PATTERN.matcher(trimmedSql).find()) {
            throw new SecurityException("Security Violation: Detected forbidden SQL keywords or injection tokens.");
        }

        // 3. Xử lý LIMIT <= 100
        Matcher limitMatcher = LIMIT_PATTERN.matcher(trimmedSql);
        if (limitMatcher.find()) {
            int currentLimit = Integer.parseInt(limitMatcher.group(1));
            if (currentLimit > 100) {
                return trimmedSql.substring(0, limitMatcher.start()) + "LIMIT 100" + trimmedSql.substring(limitMatcher.end());
            }
            return trimmedSql;
        } else {
            return trimmedSql + " LIMIT 100";
        }
    }

    /**
     * Lớp phòng vệ 2: Chống tấn công Path Traversal cho hệ thống tệp tin.
     */
    public static Path sanitizeReportPath(String baseDir, String userFileName) {
        if (baseDir == null || userFileName == null || userFileName.isBlank()) {
            throw new SecurityException("Base directory or filename cannot be null or empty.");
        }

        // Chuẩn hóa thư mục gốc và file yêu cầu
        Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolvedPath = basePath.resolve(userFileName).normalize();

        // Kiểm tra xem đường dẫn giải quyết có nằm trong base directory hay không
        if (!resolvedPath.startsWith(basePath)) {
            throw new SecurityException("Security Violation: Path traversal attempt detected with path: " + userFileName);
        }

        return resolvedPath;
    }
}
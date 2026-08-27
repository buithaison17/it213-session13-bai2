package com.example.bai2;

import com.example.bai2.dto.LogIncidentDTO;
import com.example.bai2.security.LogisticsSecurityValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LogisticsSecurityValidatorTest {
    @Test
    @DisplayName("Test Case 1: SQL An toàn -> Ép thêm LIMIT 100")
    void testCase1_SafeSql_AppendsLimit() {
        String inputSql = "SELECT * FROM deliveries WHERE hub_code = 'HN-01'";
        String validatedSql = LogisticsSecurityValidator.validateSql(inputSql);

        System.out.println("[TEST 1 OUTPUT] " + validatedSql);
        assertEquals("SELECT * FROM deliveries WHERE hub_code = 'HN-01' LIMIT 100", validatedSql);

        // Trường hợp câu lệnh đã có LIMIT > 100
        String sqlWithHighLimit = "SELECT * FROM deliveries LIMIT 500";
        String normalizedSql = LogisticsSecurityValidator.validateSql(sqlWithHighLimit);
        assertEquals("SELECT * FROM deliveries LIMIT 100", normalizedSql);
    }

    @Test
    @DisplayName("Test Case 2: SQL Độc hại -> Ném SecurityException")
    void testCase2_MaliciousSql_ThrowsSecurityException() {
        String maliciousSql = "SELECT * FROM deliveries; DROP TABLE deliveries;";

        SecurityException exception = assertThrows(SecurityException.class, () -> {
            LogisticsSecurityValidator.validateSql(maliciousSql);
        });

        System.out.println("[TEST 2 OUTPUT] Blocked malicious SQL: " + exception.getMessage());
        assertTrue(exception.getMessage().contains("Security Violation"));
    }

    @Test
    @DisplayName("Test Case 3: Path Traversal -> Ném SecurityException")
    void testCase3_PathTraversal_ThrowsSecurityException() {
        String baseDir = "C:/data/logistics";
        String maliciousPath = "../../Windows/System32/config.sys";

        SecurityException exception = assertThrows(SecurityException.class, () -> {
            LogisticsSecurityValidator.sanitizeReportPath(baseDir, maliciousPath);
        });

        System.out.println("[TEST 3 OUTPUT] Blocked Path Traversal: " + exception.getMessage());
        assertTrue(exception.getMessage().contains("Path traversal attempt detected"));
    }

    @Test
    @DisplayName("Test Case 4: PII Masking -> Khách hàng được che giấu họ tên và SĐT")
    void testCase4_PiiMasking() {
        String rawCustomer = "Nguyen Van An (0912345678)";
        String maskedResult = LogIncidentDTO.maskCustomerInfo(rawCustomer);

        System.out.println("[TEST 4.1 OUTPUT] " + maskedResult);
        assertEquals("N*** V*** A*** (091****678)", maskedResult);

        // Kiểm thử bóc tách dòng log thực tế hoàn chỉnh
        String rawLog = "[2026-08-21 08:30:15] ERROR [sorting-hub-hn] - Delivery delayed!, Tracking: RK-2026-001, Hub: HN-01, Reason: Vehicle breakdown, Customer: Nguyen Van An (Phone: 0912345678)";
        LogIncidentDTO dto = LogIncidentDTO.fromRawLog(rawLog);

        System.out.println("[TEST 4.2 LOG PARSING] " + dto);
        assertEquals("RK-2026-001", dto.trackingCode());
        assertEquals("N*** V*** A*** (091****678)", dto.maskedCustomer());
    }
}
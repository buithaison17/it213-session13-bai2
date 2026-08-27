package com.example.bai2.dto;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public record LogIncidentDTO(
        String timestamp,
        String serviceName,
        String hubCode,
        String trackingCode,
        String maskedCustomer,
        String errorMessage
) {
    private static final Pattern TRACKING_PATTERN = Pattern.compile("^RK-\\d{4}-\\d{3}$");
    private static final Pattern LOG_EXTRACTOR_PATTERN = Pattern.compile(
            "\\[(.*?)\\]\\s+ERROR\\s+\\[(.*?)\\]\\s+-\\s+(.*?),\\s+Tracking:\\s+([^,]+),\\s+Hub:\\s+([^,]+),(?:.*?),\\s+Customer:\\s+(.*)"
    );
    private static final Pattern PHONE_EXTRACTOR_PATTERN = Pattern.compile("(.*?)\\s*\\(Phone:\\s*(\\d{10})\\)");
    private static final Pattern RAW_CUSTOMER_PHONE_PATTERN = Pattern.compile("(.*?)\\s*\\((\\d{10})\\)");

    public LogIncidentDTO {
        if (trackingCode == null || !TRACKING_PATTERN.matcher(trackingCode).matches()) {
            throw new IllegalArgumentException("Invalid tracking code format: " + trackingCode);
        }
    }

    /**
     * Helper bóc tách dòng log thô thành DTO có cấu trúc và được mask PII.
     */
    public static LogIncidentDTO fromRawLog(String rawLogLine) {
        Matcher matcher = LOG_EXTRACTOR_PATTERN.matcher(rawLogLine.trim());
        if (!matcher.find()) {
            throw new IllegalArgumentException("Raw log format does not match required structure: " + rawLogLine);
        }

        String timestamp = matcher.group(1).trim();
        String serviceName = matcher.group(2).trim();
        String errorMessage = matcher.group(3).trim();
        String trackingCode = matcher.group(4).trim();
        String hubCode = matcher.group(5).trim();
        String rawCustomer = matcher.group(6).trim();

        String maskedCustomer = maskCustomerInfo(rawCustomer);

        return new LogIncidentDTO(timestamp, serviceName, hubCode, trackingCode, maskedCustomer, errorMessage);
    }

    /**
     * Logic che giấu thông tin cá nhân (PII Masking)
     * Input: "Nguyen Van An (Phone: 0912345678)" hoặc "Nguyen Van An (0912345678)"
     * Output: "N*** V*** A*** (091****678)"
     */
    public static String maskCustomerInfo(String rawInput) {
        if (rawInput == null || rawInput.isBlank()) {
            return "";
        }

        String namePart;
        String phonePart;

        Matcher phoneMatcher = PHONE_EXTRACTOR_PATTERN.matcher(rawInput.trim());
        if (phoneMatcher.find()) {
            namePart = phoneMatcher.group(1).trim();
            phonePart = phoneMatcher.group(2).trim();
        } else {
            Matcher rawPhoneMatcher = RAW_CUSTOMER_PHONE_PATTERN.matcher(rawInput.trim());
            if (rawPhoneMatcher.find()) {
                namePart = rawPhoneMatcher.group(1).trim();
                phonePart = rawPhoneMatcher.group(2).trim();
            } else {
                return rawInput;
            }
        }

        // Mask tên: "Nguyen Van An" -> "N*** V*** A***"
        String maskedName = Arrays.stream(namePart.split("\\s+"))
                .map(word -> word.isEmpty() ? "" : word.charAt(0) + "***")
                .collect(Collectors.joining(" "));

        // Mask số điện thoại: Ẩn 4 số giữa "0912345678" -> "091****678"
        String maskedPhone = phonePart.substring(0, 3) + "****" + phonePart.substring(7);

        return maskedName + " (" + maskedPhone + ")";
    }
}
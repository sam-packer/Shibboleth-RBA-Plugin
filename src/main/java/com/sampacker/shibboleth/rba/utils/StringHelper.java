package com.sampacker.shibboleth.rba.utils;

import jakarta.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class StringHelper
{
    public static final int MAX_STRING_LEN = 256; // max length for any string field

    public static String sanitizeString(String s)
    {
        if (s == null)
        {
            return "";
        }
        // Remove control characters (including newlines) to avoid log injection and size issues
        String cleaned = s.replaceAll("\\p{Cntrl}", "").trim();
        if (cleaned.length() > MAX_STRING_LEN)
        {
            return cleaned.substring(0, MAX_STRING_LEN);
        }
        return cleaned;
    }

    public static String safeString(String s)
    {
        if (s == null)
        {
            return "";
        }
        return sanitizeString(s);
    }

    public static String readAll(InputStream is) throws IOException
    {
        if (is == null)
        {
            return "";
        }
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)))
        {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null)
            {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    public static String extractClientIp(HttpServletRequest req)
    {
        final String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank())
        {
            final String first = xff.split(",")[0].trim();
            if (!first.isEmpty())
            {
                return first;
            }
        }
        return req.getRemoteAddr();
    }

    public static String maskPayloadForLogs(String json)
    {
        if (json == null)
        {
            return "";
        }
        if (json.length() <= 512)
        {
            return json;
        }
        return json.substring(0, 256) + "...[truncated:" + json.length() + " bytes]";
    }
}

package burp;

public class ContextTrimmer {
    
    public static String trim(String content, int maxSize) {
        if (content == null) {
            return "";
        }
        
        if (content.length() <= maxSize) {
            return content;
        }
        
        // Try to find a good break point (end of line)
        int trimPoint = maxSize - 100; // Leave room for message
        int lastNewline = content.lastIndexOf('\n', trimPoint);
        
        if (lastNewline > maxSize / 2) {
            // Good break point found
            trimPoint = lastNewline;
        } else {
            trimPoint = maxSize - 100;
        }
        
        String trimmed = content.substring(0, trimPoint);
        trimmed += "\n\n[... Content trimmed. Original size: " + content.length() + 
                   " characters, showing first " + trimPoint + " characters ...]";
        
        return trimmed;
    }
    
    public static String trimWithPriority(String headers, String body, int maxSize) {
        // Always keep headers, trim body if needed
        if (headers == null) headers = "";
        if (body == null) body = "";
        
        int totalLength = headers.length() + body.length() + 2; // +2 for \n\n separator
        
        if (totalLength <= maxSize) {
            return headers + "\n\n" + body;
        }
        
        // Headers take priority
        int availableForBody = maxSize - headers.length() - 2;
        if (availableForBody < 100) {
            // Not enough space, trim both
            int headerLimit = maxSize / 2;
            int bodyLimit = maxSize / 2;
            return trim(headers, headerLimit) + "\n\n" + trim(body, bodyLimit);
        }
        
        return headers + "\n\n" + trim(body, availableForBody);
    }
}

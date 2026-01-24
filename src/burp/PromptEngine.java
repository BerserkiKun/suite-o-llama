package burp;

import java.util.HashMap;
import java.util.Map;

public class PromptEngine {
    private final ExtensionState state;
    private final IExtensionHelpers helpers;
    
    public PromptEngine(ExtensionState state) {
        this.state = state;
        this.helpers = state.getHelpers();
    }
    
    public String processTemplate(String template, RequestContext context) {
        if (context == null || context.getRequest() == null) {
            return template;
        }
        
        Map<String, String> variables = extractVariables(context);
        String processed = template;
        
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            processed = processed.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        
        return processed;
    }
    
    private Map<String, String> extractVariables(RequestContext context) {
        Map<String, String> vars = new HashMap<>();
        
        byte[] request = context.getRequest();
        if (request == null) {
            return vars;
        }
        
        IRequestInfo reqInfo = helpers.analyzeRequest(context.getService(), request);
        
        // Extract method
        vars.put("method", reqInfo.getMethod());
        
        // Extract URL
        vars.put("url", reqInfo.getUrl().toString());
        
        // Extract headers
        StringBuilder headers = new StringBuilder();
        for (String header : reqInfo.getHeaders()) {
            if (shouldRedactHeader(header)) {
                headers.append(redactHeader(header)).append("\n");
            } else {
                headers.append(header).append("\n");
            }
        }
        vars.put("headers", headers.toString().trim());
        
        // Extract body
        int bodyOffset = reqInfo.getBodyOffset();
        String body = "";
        if (bodyOffset < request.length) {
            byte[] bodyBytes = new byte[request.length - bodyOffset];
            System.arraycopy(request, bodyOffset, bodyBytes, 0, bodyBytes.length);
            body = new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
        }
        vars.put("body", body);
        
        // Full request
        String fullRequest = new String(request, java.nio.charset.StandardCharsets.UTF_8);
        if (state.isRedactAuthHeaders() || state.isRedactCookies()) {
            fullRequest = redactSensitiveData(fullRequest);
        }
        
        // Apply context size limit
        fullRequest = ContextTrimmer.trim(fullRequest, state.getMaxContextSize());
        vars.put("full_request", fullRequest);
        
        // Full response (if available)
        if (context.hasResponse()) {
            String fullResponse = new String(context.getResponse(), java.nio.charset.StandardCharsets.UTF_8);
            fullResponse = ContextTrimmer.trim(fullResponse, state.getMaxContextSize());
            vars.put("full_response", fullResponse);
        } else {
            vars.put("full_response", "");
        }
        
        return vars;
    }
    
    private boolean shouldRedactHeader(String header) {
        String lowerHeader = header.toLowerCase();
        
        if (state.isRedactAuthHeaders()) {
            if (lowerHeader.startsWith("authorization:") || 
                lowerHeader.startsWith("x-api-key:") ||
                lowerHeader.startsWith("x-auth-token:")) {
                return true;
            }
        }
        
        if (state.isRedactCookies()) {
            if (lowerHeader.startsWith("cookie:")) {
                return true;
            }
        }
        
        return false;
    }
    
    private String redactHeader(String header) {
        int colonIdx = header.indexOf(':');
        if (colonIdx > 0) {
            return header.substring(0, colonIdx + 1) + " [REDACTED]";
        }
        return header;
    }
    
    private String redactSensitiveData(String content) {
        String redacted = content;
        
        if (state.isRedactAuthHeaders()) {
            redacted = redacted.replaceAll("(?i)(Authorization|X-API-Key|X-Auth-Token):\\s*[^\r\n]+", 
                                          "$1: [REDACTED]");
        }
        
        if (state.isRedactCookies()) {
            redacted = redacted.replaceAll("(?i)Cookie:\\s*[^\r\n]+", "Cookie: [REDACTED]");
        }
        
        return redacted;
    }
    
    public String createAnalysisPrompt(RequestContext context, String userPrompt) {
        if (userPrompt == null || userPrompt.trim().isEmpty()) {
            userPrompt = "Analyze this HTTP request for security vulnerabilities:\n\n{{full_request}}";
        }
        return processTemplate(userPrompt, context);
    }
    
    public String createPayloadPrompt(RequestContext context, String parameterName, String parameterValue) {
        String template = "Generate security testing payloads for the parameter '" + parameterName + 
                         "' with current value: " + parameterValue + "\n\n" +
                         "Request context:\n{{method}} {{url}}\n\n" +
                         "Provide 5-10 ranked payloads. Format: one payload per line, no explanations.";
        return processTemplate(template, context);
    }
}

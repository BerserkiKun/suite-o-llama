package burp;

import java.util.concurrent.*;

public class AutocompleteEngine {
    private final ExtensionState state;
    private final OllamaClient ollamaClient;
    private final PromptEngine promptEngine;
    private final ExecutorService executor;
    private final ConcurrentHashMap<String, String[]> cache;
    private final Semaphore rateLimiter;
    
    public AutocompleteEngine(ExtensionState state, OllamaClient ollamaClient, 
                            PromptEngine promptEngine) {
        this.state = state;
        this.ollamaClient = ollamaClient;
        this.promptEngine = promptEngine;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("Suite-o-llama-Autocomplete");
            return t;
        });
        this.cache = new ConcurrentHashMap<>();
        this.rateLimiter = new Semaphore(1); // Only one request at a time
    }
    
    public interface PayloadCallback {
        void onPayloadsGenerated(String[] payloads);
    }
    
    public void generatePayloads(RequestContext context, String paramContext, 
                               PayloadCallback callback) {
        // Check cache first
        String cacheKey = createCacheKey(context, paramContext);
        if (cache.containsKey(cacheKey)) {
            callback.onPayloadsGenerated(cache.get(cacheKey));
            return;
        }
        
        // Rate limiting - only process if not already generating
        if (!rateLimiter.tryAcquire()) {
            callback.onPayloadsGenerated(new String[0]);
            return;
        }
        
        executor.submit(() -> {
            try {
                String[] payloads = generatePayloadsInternal(context, paramContext);
                cache.put(cacheKey, payloads);
                callback.onPayloadsGenerated(payloads);
            } catch (Exception e) {
                state.getStderr().println("Autocomplete error: " + e.getMessage());
                callback.onPayloadsGenerated(new String[0]);
            } finally {
                rateLimiter.release();
            }
        });
    }
    
    private String[] generatePayloadsInternal(RequestContext context, String paramContext) {
        try {
            // Create lightweight prompt for payload generation
            String prompt = "Generate 5 security testing payloads for this parameter context:\n" +
                          paramContext + "\n\n" +
                          "Output format: one payload per line, no explanations.\n" +
                          "Focus on: SQLi, XSS, command injection.";
            
            // Trim prompt to avoid bloat
            prompt = ContextTrimmer.trim(prompt, 500);
            
            String response = ollamaClient.generate(prompt, state.getPayloadModel());
            
            // Parse response into individual payloads
            return parsePayloads(response);
            
        } catch (Exception e) {
            state.getStderr().println("Payload generation failed: " + e.getMessage());
            return new String[0];
        }
    }
    
    private String[] parsePayloads(String response) {
        if (response == null || response.trim().isEmpty()) {
            return new String[0];
        }
        
        String[] lines = response.split("\n");
        java.util.List<String> payloads = new java.util.ArrayList<>();
        
        for (String line : lines) {
            line = line.trim();
            // Skip empty lines, headers, explanations
            if (line.isEmpty() || 
                line.startsWith("#") || 
                line.startsWith("//") ||
                line.length() > 200 ||
                line.toLowerCase().contains("payload") && line.endsWith(":")) {
                continue;
            }
            
            // Remove common prefixes
            line = line.replaceFirst("^\\d+\\.\\s*", "");
            line = line.replaceFirst("^-\\s*", "");
            line = line.replaceFirst("^\\*\\s*", "");
            
            if (!line.isEmpty()) {
                payloads.add(line);
            }
            
            // Limit to 10 payloads
            if (payloads.size() >= 10) {
                break;
            }
        }
        
        return payloads.toArray(new String[0]);
    }
    
    private String createCacheKey(RequestContext context, String paramContext) {
        // Simple cache key based on URL and param context
        String url = context.hasService() ? context.getServiceInfo() : "unknown";
        return url + ":" + paramContext.hashCode();
    }
    
    public void clearCache() {
        cache.clear();
    }
    
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}

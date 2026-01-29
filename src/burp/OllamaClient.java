package burp;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import org.json.*;

public class OllamaClient {
    private final ExtensionState state;
    private final ExecutorService executor;
    private Future<?> currentRequest;
    
    // Added streaming and cancellation fields in v2.2.0
    private volatile HttpURLConnection currentConnection;
    private volatile boolean cancelled = false;
    private volatile boolean streaming = false;
    
    public OllamaClient(ExtensionState state) {
        this.state = state;
        this.executor = Executors.newFixedThreadPool(3, r -> {  // Changed from SingleThread to FixedThreadPool(3)
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("Suite-o-llama-Worker");
            return t;
        });
    }
    
    public interface ResponseCallback {
        void onSuccess(String response, long timeMs, int estimatedTokens);
        void onError(String error);
        void onCancelled(long cancelTimeMs); // NEW: Cancellation callback
    }
    
    public void generateAsync(String prompt, String model, ResponseCallback callback) {
        if (currentRequest != null && !currentRequest.isDone()) {
            currentRequest.cancel(true);
        }
        
        // Reset cancellation state
        cancelled = false;
        streaming = false;
        
        currentRequest = executor.submit(() -> {
            try {
                long startTime = System.currentTimeMillis();
                String response = generate(prompt, model);
                long elapsed = System.currentTimeMillis() - startTime;
                int tokens = estimateTokens(response);
                
                if (!Thread.currentThread().isInterrupted() && !cancelled) {
                    callback.onSuccess(response, elapsed, tokens);
                } else {
                    callback.onCancelled(System.currentTimeMillis() - startTime);
                }
            } catch (InterruptedException e) {
                callback.onCancelled(0); // Immediate cancellation
            } catch (Exception e) {
                if (!cancelled) {
                    callback.onError(e.getMessage());
                } else {
                    callback.onCancelled(System.currentTimeMillis() - getRequestStartTime());
                }
            } finally {
                currentConnection = null;
            }
        });
    }
    
    // NEW: Track when request started for timing
    private long requestStartTime = 0;
    private long getRequestStartTime() {
        return requestStartTime > 0 ? requestStartTime : System.currentTimeMillis();
    }
    
    public String generate(String prompt, String model) throws Exception {
        // Reset state before new request
        cancelled = false;
        streaming = true;
        requestStartTime = System.currentTimeMillis();
    
        // Close any existing connection first
        if (currentConnection != null) {
            try {
                currentConnection.disconnect();
            } catch (Exception e) {
                // Ignore
            }
            currentConnection = null;
        }

        URL url = new URL(state.getOllamaEndpoint() + "/api/generate");
        currentConnection = (HttpURLConnection) url.openConnection();
        
        try {
            currentConnection.setRequestMethod("POST");
            currentConnection.setRequestProperty("Content-Type", "application/json");
            currentConnection.setDoOutput(true);
            currentConnection.setConnectTimeout(5000);
            currentConnection.setReadTimeout(150000); // Increased time form 2 minutes to 2 minutes 30 seconds
            
            JSONObject requestBody = new JSONObject();
            requestBody.put("model", model);
            requestBody.put("prompt", prompt);
            requestBody.put("stream", true); // Enable streaming v2.2.0
            requestBody.put("options", new JSONObject()
                .put("temperature", state.getTemperature())
                .put("num_predict", state.getMaxTokens())
            );
            
            try (OutputStream os = currentConnection.getOutputStream()) {
                byte[] input = requestBody.toString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            
            int responseCode = currentConnection.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("Ollama returned status " + responseCode);
            }
            
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(currentConnection.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (cancelled || Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException("Generation cancelled by user");
                    }
                    
                    if (!line.trim().isEmpty()) {
                        JSONObject jsonResponse = new JSONObject(line);
                        if (jsonResponse.has("response")) {
                            String token = jsonResponse.getString("response");
                            response.append(token);
                        }
                    }
                }
            }
            
            return response.toString();
            
        } finally {
            currentConnection = null;
            streaming = false;
        }
    }

    // method to read error stream
    private String readErrorStream(HttpURLConnection conn) {
        try {
            InputStream errorStream = conn.getErrorStream();
            if (errorStream != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(errorStream));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                return sb.toString();
            }
        } catch (Exception e) {
        }
        return "";
    }
    
    // Enhanced cancellation with immediate response v2.2.0
    public void cancel() {
        long cancelStartTime = System.currentTimeMillis();
        cancelled = true;
        
        // 1. Immediately disconnect HTTP connection (fastest)
        if (currentConnection != null) {
            currentConnection.disconnect();
            state.getStdout().println("HTTP connection disconnected immediately");
        }
        
        // 2. Cancel the Future/thread
        if (currentRequest != null && !currentRequest.isDone()) {
            currentRequest.cancel(true);
            state.getStdout().println("Request thread interrupted");
        }
        
        // 3. Stop streaming flag
        streaming = false;
        
        long cancelTime = System.currentTimeMillis() - cancelStartTime;
        state.getStdout().println("Cancellation completed in " + cancelTime + "ms");
    }
    
    // Check if currently streaming
    public boolean isStreaming() {
        return streaming;
    }
    
    // Check if cancelled
    public boolean isCancelled() {
        return cancelled;
    }
    
    // rest of the methods (checkHealth, getAvailableModels, etc.) ...
    public boolean checkHealth() {
    try {
        URL url = new URL(state.getOllamaEndpoint() + "/api/tags");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        
        int code = conn.getResponseCode();
        conn.disconnect();
        return code == 200;
    } catch (Exception e) {
        return false;
    }
}

public String[] getAvailableModels() {
    try {
        URL url = new URL(state.getOllamaEndpoint() + "/api/tags");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(5000);
        
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        
        JSONObject json = new JSONObject(response.toString());
        JSONArray models = json.getJSONArray("models");
        String[] modelNames = new String[models.length()];
        for (int i = 0; i < models.length(); i++) {
            modelNames[i] = models.getJSONObject(i).getString("name");
        }
        return modelNames;
        
    } catch (Exception e) {
        state.getStderr().println("Error fetching models: " + e.getMessage());
        return new String[0];
    }
}

public boolean isModelAvailable(String modelName) {
    String[] models = getAvailableModels();
    for (String model : models) {
        if (model.equals(modelName) || model.startsWith(modelName + ":")) {
            return true;
        }
    }
    return false;
}

public void shutdown() {
    if (executor != null) {
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
private int estimateTokens(String text) {
    // Rough estimate: ~4 characters per token
    return text.length() / 4;
}
}
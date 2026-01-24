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
    
    public OllamaClient(ExtensionState state) {
        this.state = state;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("Suite-o-llama-Worker");
            return t;
        });
    }
    
    public interface ResponseCallback {
        void onSuccess(String response, long timeMs, int estimatedTokens);
        void onError(String error);
    }
    
    public void generateAsync(String prompt, String model, ResponseCallback callback) {
        if (currentRequest != null && !currentRequest.isDone()) {
            currentRequest.cancel(true);
        }
        
        currentRequest = executor.submit(() -> {
            try {
                long startTime = System.currentTimeMillis();
                String response = generate(prompt, model);
                long elapsed = System.currentTimeMillis() - startTime;
                int tokens = estimateTokens(response);
                
                if (!Thread.currentThread().isInterrupted()) {
                    callback.onSuccess(response, elapsed, tokens);
                }
            } catch (InterruptedException e) {
                callback.onError("Request cancelled");
            } catch (Exception e) {
                callback.onError(e.getMessage());
            }
        });
    }
    
    public String generate(String prompt, String model) throws Exception {
        URL url = new URL(state.getOllamaEndpoint() + "/api/generate");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(120000); // 2 minutes for generation
            
            JSONObject requestBody = new JSONObject();
            requestBody.put("model", model);
            requestBody.put("prompt", prompt);
            requestBody.put("stream", false);
            requestBody.put("options", new JSONObject()
                .put("temperature", state.getTemperature())
                .put("num_predict", state.getMaxTokens())
            );
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.toString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("Ollama returned status " + responseCode);
            }
            
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException();
                    }
                    response.append(line);
                }
            }
            
            JSONObject jsonResponse = new JSONObject(response.toString());
            return jsonResponse.getString("response");
            
        } finally {
            conn.disconnect();
        }
    }
    
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
    
    public void cancel() {
        if (currentRequest != null && !currentRequest.isDone()) {
            currentRequest.cancel(true);
        }
    }
    
    private int estimateTokens(String text) {
        // Rough estimate: ~4 characters per token
        return text.length() / 4;
    }
    
    public void shutdown() {
        cancel();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}
